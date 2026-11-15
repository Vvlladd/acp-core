//! Every git call, each bounded by `GIT_OP_TIMEOUT`: worktree lifecycle, diffs, integrate commits.
//! Implemented in T18 (`reports/03-design.md` § `src/workspace/git.rs`).
//!
//! Rules this module exists to enforce (design, § `src/workspace/git.rs`):
//!
//! - git is always invoked with an **argv vector** — never a shell string, never `libgit2`, so
//!   worktree and reflog behaviour is exactly what the human sees on the command line. The program
//!   is an **absolute path** resolved from absolute `PATH` entries only, and the child environment
//!   is built from scratch: a git call runs with a worker's worktree as its cwd, so a relative or
//!   empty `PATH` entry would let that worker supply the `git` the daemon executes.
//! - **S4**: every ref is preceded by `--end-of-options` and every path list by `--`, so a ref or
//!   path that starts with `-` can never become a flag. Refs are resolved to a validated 40-hex sha
//!   before any subsequent call uses them.
//! - **S7**: `commit_all` builds the commit message itself — the caller supplies a title and a body,
//!   never trailers. Any line in the body that looks like an `Acp-<word>-Id:` trailer is stripped,
//!   so worker-authored text can never forge the gate/run identity the control plane reconciles on.
//! - Every child process is wrapped in `tokio::time::timeout(GIT_OP_TIMEOUT, …)` and killed on
//!   expiry (decision 11), so a hung git can never wedge a run — it fails with [`GitError::Timeout`].
//!
//! Character-class validation of caller input (a `base_ref` that starts with `-`, a path that
//! escapes the repo) is `core::policy`'s job, not this module's: here the `--end-of-options` / `--`
//! discipline is what makes such input harmless, and git itself rejects what it cannot resolve.
//!
//! No `regex` dependency: the sha and trailer predicates are hand-written char checks.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::future::Future;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::RwLock;
use std::time::Duration;

use globset::GlobSet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

pub mod audit;

/// How long any single git invocation may take before it is killed (design, decision 11).
pub const GIT_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// How many paths one `git add` is given. Well under `ARG_MAX` at any plausible path length, and
/// large enough that a normal change set is one call.
const STAGE_BATCH: usize = 64;

/// Longest commit subject `commit_all` will emit, in bytes (git's own soft limit).
pub const MAX_SUBJECT_BYTES: usize = 72;

/// Subject used when the supplied title sanitizes to nothing — `git commit` refuses an empty message.
const FALLBACK_SUBJECT: &str = "(no title)";

/// How much of an untracked file `frozen_diff` inlines before truncating it.
const MAX_UNTRACKED_DIFF_BYTES: usize = 256 * 1024;

/// Maximum bytes retained from the complete frozen diff before its truncation marker.
///
/// This is one assembled-document budget, shared by the worktree and staged-index freezes. It is
/// deliberately public so callers and tests can state the operational bound without duplicating a
/// magic number.
pub const MAX_FROZEN_DIFF_BYTES: usize = 8 * 1024 * 1024;

/// Appended exactly once when the complete frozen diff exceeds [`MAX_FROZEN_DIFF_BYTES`].
pub const FROZEN_DIFF_TRUNCATION_MARKER: &[u8] =
    b"\n(frozen diff truncated by the control plane)\n";

/// Bounds for the host-verification source inventory. The inventory deliberately covers the
/// complete tracked checkout plus all ignored and untracked files, not merely the frozen patch.
pub const MAX_SOURCE_INVENTORY_PATHS: usize = 20_000;
pub const MAX_SOURCE_INVENTORY_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SOURCE_INVENTORY_BYTES: usize = 64 * 1024 * 1024;
const MAX_SOURCE_INVENTORY_LIST_BYTES: usize = 8 * 1024 * 1024;
const MAX_SOURCE_INVENTORY_SUBMODULE_DEPTH: usize = 8;
const MAX_SOURCE_INVENTORY_DIRECTORY_DEPTH: usize = 128;

/// Error text retained from a streaming git child. The pipe is drained beyond this bound so a
/// noisy child cannot deadlock, but an error cannot make the daemon retain unbounded stderr.
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;

/// Retirement journals contain only one filesystem identity and two recovery paths. Bound reads
/// so a damaged or replaced receipt cannot make inventory or confirmation allocate arbitrarily.
const MAX_RETIREMENT_IDENTITY_BYTES: u64 = 64 * 1024;
const RETIREMENT_RECEIPT_VERSION: u32 = 2;

/// `core.hooksPath` for every commit the control plane makes.
///
/// A path that **exists and can never become a directory**, so no hook of any name can ever be
/// found under it: `open("/dev/null/pre-commit")` is `ENOTDIR` on any POSIX system. An empty
/// directory would do the same job only for as long as it stayed empty, and one under `/tmp` or the
/// state dir is something another process can populate between two commits; this cannot be planted
/// in, needs no creation and no cleanup, and gives `commit_staged` no reason to know where the
/// state dir is.
const NO_HOOKS_PATH: &str = "/dev/null";

/// The two modes git stores a regular file under. Which one a new file gets is part of the diff, so
/// both freezes have to derive it the same way or an executable script is reviewed as an ordinary
/// file — and then the approval's re-freeze disagrees with the review and can never commit
/// (round-4 review, finding 2).
const MODE_FILE: &str = "100644";
const MODE_EXEC: &str = "100755";

/// Longest worker-chosen string (a path, a symlink target) `frozen_diff` interpolates into a
/// synthetic diff header.
const MAX_DIFF_TOKEN_BYTES: usize = 512;

/// Test-only override of [`GIT_OP_TIMEOUT`], honoured only in debug builds. See [`git_op_timeout`].
/// It does not exist at all in a release build — the name is compiled out with the branch that
/// reads it, which is the point.
#[cfg(any(debug_assertions, test))]
const TEST_TIMEOUT_ENV: &str = "ACP_TEST_GIT_TIMEOUT_MS";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Every way a git call can fail. `Timeout` is the one the loop maps to
/// `run.status{blocked, reason}` and `PolicyCode::GitTimeout`.
#[derive(Debug, Error)]
pub enum GitError {
    #[error("git recovery: {reason}")]
    RecoveryInvalid { reason: String },
    #[error("git {op} timed out after {secs}s")]
    Timeout { op: &'static str, secs: u64 },
    #[error("git {op} failed ({status}): {message}")]
    Failed {
        op: &'static str,
        status: String,
        message: String,
    },
    #[error("git {op}: expected a 40-hex object name, got {value:?}")]
    InvalidRef { op: &'static str, value: String },
    #[error("git {op}: {source}")]
    Io {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },
}

/// One entry of `git status --porcelain -z`: the two-character `XY` code and the path it applies to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChangedFile {
    pub path: String,
    pub status: String,
}

impl ChangedFile {
    /// `??` — the file exists in the worktree and git does not track it.
    pub fn is_untracked(&self) -> bool {
        self.status == "??"
    }
}

/// What `frozen_diff` wrote, in the shape the `diff.frozen` event carries, plus the untracked paths
/// it refused to inline.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DiffStat {
    pub files: Vec<String>,
    pub added: u64,
    pub deleted: u64,
    /// sha256 of the exact bounded artifact written to disk.
    pub diff_hash: String,
    /// Untracked paths whose **contents were deliberately not read**: the path is a symlink, passes
    /// through a symlinked directory, resolves outside the worktree, or is not a regular file. The
    /// diff names them and, for a symlink, records its target — never the target's contents. A
    /// caller may surface these as a policy signal; a worker planting one is trying to read a file
    /// its sandbox denies it.
    pub symlinks: Vec<String>,
}

/// One changed path that matched the denylist, with the indices of the globs it matched (indices
/// into the `GlobSet` the caller built, so the caller can name the pattern in the violation).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DenylistHit {
    pub path: String,
    pub glob_indices: Vec<usize>,
}

/// The two caller-supplied halves of a commit message. Trailers are **not** part of it: they are
/// passed separately to [`commit_all`], which is the only thing that may create one (S7).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CommitMessage {
    pub title: String,
    pub body: String,
}

/// A preview names the directory and its linked-worktree control file at the time of selection.
/// A missing directory is valid only for the existing journal-recovery path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum PreviewCheckout {
    Absent,
    Present {
        root: (u64, u64),
        git_file: Option<(u64, u64, i64, i64)>,
    },
}

impl PreviewCheckout {
    pub(crate) fn capture(path: &Path) -> std::io::Result<Self> {
        let root = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::Absent),
            Err(error) => return Err(error),
        };
        if !root.is_dir() {
            return Err(std::io::Error::other("the worktree path is not a directory"));
        }
        let git_file = match std::fs::symlink_metadata(path.join(".git")) {
            Ok(meta) if meta.is_file() => Some((meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec())),
            Ok(_) => return Err(std::io::Error::other("the worktree .git entry is not a regular file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        Ok(Self::Present { root: (root.dev(), root.ino()), git_file })
    }
}

/// Filesystem and Git-admin identity captured immediately before a retirement Trash handoff.
/// The device/inode pair binds the later recovery record to the directory that was validated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetirementTicket {
    #[serde(default)]
    version: u32,
    pub preserved_ref: String,
    root_dev: u64,
    root_ino: u64,
    git_file: Vec<u8>,
    #[serde(default)]
    common_dir: PathBuf,
    #[serde(default)]
    git_admin_name: String,
    git_dir_dev: u64,
    git_dir_ino: u64,
    #[serde(default)]
    trash_path: Option<PathBuf>,
    #[serde(default)]
    git_quarantine_path: Option<PathBuf>,
    #[serde(default)]
    registration_retired: bool,
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Absolute path of the working tree containing `cwd`.
pub async fn repo_root(cwd: &Path) -> Result<PathBuf, GitError> {
    let out = git("repo_root", cwd, [tok("rev-parse"), tok("--show-toplevel")]).await?;
    Ok(PathBuf::from(trim_eol(&out.stdout())))
}

/// Where git keeps `name` for the repository containing `cwd` — `git rev-parse --git-path`.
///
/// The reason this is a git call and not a `join` is the **linked worktree**: there, `.git` is a
/// *file* pointing at `<main>/.git/worktrees/<name>/`, and files git treats as common (`info/`,
/// `objects/`, `config`) live in the main git dir while per-worktree files do not. Only git knows
/// which is which, so only git may answer — hard-coding `<repo>/.git/info/exclude` produces a path
/// that does not exist in a worktree, and a "remedy" that writes to it would be a lie.
///
/// The answer may be relative — git gives it relative to the **current directory** — so it is
/// joined onto `cwd` when it is.
pub async fn git_path(cwd: &Path, name: &str) -> Result<PathBuf, GitError> {
    // No `--end-of-options` here, deliberately: `--git-path` takes the *next* token as its
    // argument, so the separator would be consumed as the name. Every call site passes a literal
    // (`info/exclude`), so there is no caller-influenced value to separate.
    let out = git(
        "git_path",
        cwd,
        [tok("rev-parse"), tok("--git-path"), OsStr::new(name)],
    )
    .await?;
    let path = PathBuf::from(trim_eol(&out.stdout()));
    if path.is_absolute() {
        return Ok(path);
    }
    // git answers relative to the **current directory** (`../.git/info/exclude` from a subdir), so
    // that is what it is joined onto. From a linked worktree the answer is absolute and already
    // points into the main git dir, which is the branch above.
    Ok(cwd.join(path))
}

/// Resolve `r` to the 40-hex sha of the commit it names.
///
/// `r` is caller-influenced, so it goes after `--end-of-options` (S4) and the result is validated:
/// anything that is not exactly 40 lowercase hex characters is [`GitError::InvalidRef`], and no
/// other function in this module accepts a sha it has not seen validated.
pub async fn resolve_ref(repo: &Path, r: &str) -> Result<String, GitError> {
    let rev = format!("{r}^{{commit}}");
    let out = git(
        "resolve_ref",
        repo,
        [
            tok("rev-parse"),
            tok("--verify"),
            tok("--end-of-options"),
            OsStr::new(&rev),
        ],
    )
    .await?;
    checked_sha("resolve_ref", out.stdout().trim())
}

/// Validate a recorded recovery draft without resetting or copying any files. The caller wraps
/// this sequence in one GIT_OP_TIMEOUT, outside the core actor.
pub async fn recovery_status(
    repo: &Path,
    worktree: &Path,
    base_sha: &str,
) -> Result<String, GitError> {
    let invalid = || {
        GitError::RecoveryInvalid { reason:
        "The preserved draft is missing, redirected, belongs to another repository, or its base commit changed.".into() }
    };
    let canonical_repo = tokio::fs::canonicalize(repo).await.map_err(|_| invalid())?;
    let relative = worktree.strip_prefix(repo).map_err(|_| invalid())?;
    if !relative.starts_with(".acp/worktrees") {
        return Err(invalid());
    }
    let canonical = tokio::fs::canonicalize(worktree)
        .await
        .map_err(|_| invalid())?;
    // macOS's /var and /tmp aliases may occur above the repository. Links within the draft path
    // still fail: its canonical location must be exactly the same suffix under the real root.
    let top = tokio::fs::canonicalize(repo_root(worktree).await?)
        .await
        .map_err(|_| invalid())?;
    if canonical != canonical_repo.join(relative)
        || top != canonical
        || head_sha(worktree).await? != base_sha
    {
        return Err(invalid());
    }
    async fn common_dir(path: &Path) -> Result<PathBuf, GitError> {
        let out = git(
            "recovery_repository",
            path,
            [
                tok("rev-parse"),
                tok("--path-format=absolute"),
                tok("--git-common-dir"),
            ],
        )
        .await?;
        let dir = PathBuf::from(trim_eol(&out.stdout()));
        tokio::fs::canonicalize(&dir)
            .await
            .map_err(|source| GitError::Io {
                op: "recovery_repository",
                source,
            })
    }
    if common_dir(repo).await? != common_dir(worktree).await? {
        return Err(invalid());
    }
    status_porcelain(worktree).await
}

fn retirement_invalid(reason: impl Into<String>) -> GitError {
    GitError::RecoveryInvalid {
        reason: reason.into(),
    }
}

fn retirement_identity(store: &Path, run: &str, lineage: &str) -> PathBuf {
    store
        .join("retired")
        .join(run)
        .join(format!("{lineage}.identity"))
}

fn registration_recovery_path(common: &Path, run: &str, lineage: &str) -> PathBuf {
    common
        .join("acp-retired-worktrees")
        .join(run)
        .join(format!("{lineage}.git-admin"))
}

fn c_name(value: &OsStr) -> Result<CString, GitError> {
    CString::new(value.as_bytes())
        .map_err(|_| retirement_invalid("a retirement path component contains a NUL byte"))
}

fn open_dir_at(parent: BorrowedFd<'_>, name: &OsStr, create: bool) -> Result<OwnedFd, GitError> {
    let name = c_name(name)?;
    if create {
        // SAFETY: the parent descriptor and NUL-terminated component are valid for this call.
        let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if rc != 0 {
            let source = std::io::Error::last_os_error();
            if source.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(GitError::Io {
                    op: "retirement_directory",
                    source,
                });
            }
        }
    }
    // SAFETY: the parent descriptor and NUL-terminated component are valid. O_NOFOLLOW refuses
    // repository-controlled symlinks instead of allowing them to redirect cleanup state.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(GitError::Io {
            op: "retirement_directory",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: successful openat returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn retirement_run_dir_sync(store: &Path, run: &str, create: bool) -> Result<OwnedFd, GitError> {
    if Path::new(run).components().count() != 1
        || !matches!(
            Path::new(run).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(retirement_invalid(
            "the retirement run id is not a path component",
        ));
    }
    let canonical_store = std::fs::canonicalize(store).map_err(|source| GitError::Io {
        op: "retirement_directory",
        source,
    })?;
    let raw = CString::new(canonical_store.as_os_str().as_bytes())
        .map_err(|_| retirement_invalid("the retirement state path contains a NUL byte"))?;
    // SAFETY: raw is a valid NUL-terminated canonical path. O_NOFOLLOW binds the trusted anchor.
    let fd = unsafe {
        libc::open(
            raw.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(GitError::Io {
            op: "retirement_directory",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: successful open returned a new owned descriptor.
    let root = unsafe { OwnedFd::from_raw_fd(fd) };
    let retired = open_dir_at(root.as_fd(), OsStr::new("retired"), create)?;
    open_dir_at(retired.as_fd(), OsStr::new(run), create)
}

async fn retirement_run_dir(store: &Path, run: &str, create: bool) -> Result<OwnedFd, GitError> {
    retirement_run_dir_sync(store, run, create)
}

fn registration_run_dir_sync(common: &Path, run: &str, create: bool) -> Result<OwnedFd, GitError> {
    if Path::new(run).components().count() != 1
        || !matches!(
            Path::new(run).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(retirement_invalid(
            "the retirement run id is not a path component",
        ));
    }
    let canonical_common = std::fs::canonicalize(common).map_err(|source| GitError::Io {
        op: "retirement_deregister",
        source,
    })?;
    let raw = CString::new(canonical_common.as_os_str().as_bytes())
        .map_err(|_| retirement_invalid("the Git common directory contains a NUL byte"))?;
    // SAFETY: raw is a canonical, NUL-terminated path. O_NOFOLLOW binds the Git common directory.
    let fd = unsafe {
        libc::open(
            raw.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(GitError::Io {
            op: "retirement_deregister",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: successful open returned a new owned descriptor.
    let root = unsafe { OwnedFd::from_raw_fd(fd) };
    let retired = open_dir_at(root.as_fd(), OsStr::new("acp-retired-worktrees"), create)?;
    open_dir_at(retired.as_fd(), OsStr::new(run), create)
}

async fn registration_run_dir(common: &Path, run: &str, create: bool) -> Result<OwnedFd, GitError> {
    registration_run_dir_sync(common, run, create)
}

async fn save_retirement_identity(
    store: &Path,
    run: &str,
    lineage: &str,
    ticket: &RetirementTicket,
) -> Result<(), GitError> {
    let bytes = serde_json::to_vec(ticket).map_err(|error| {
        retirement_invalid(format!("could not encode cleanup identity: {error}"))
    })?;
    let dir = retirement_run_dir(store, run, true).await?;
    let final_name = c_name(OsStr::new(&format!("{lineage}.identity")))?;
    let temporary_name = c_name(OsStr::new(&format!("{lineage}.identity.tmp")))?;
    // A stale temporary (including a hostile symlink) is only unlinked by name beneath the bound
    // directory. O_EXCL below then closes the unlink/create symlink race.
    // SAFETY: descriptor and names are valid; unlinkat never follows the named symlink.
    unsafe { libc::unlinkat(dir.as_raw_fd(), temporary_name.as_ptr(), 0) };
    // SAFETY: descriptor and name are valid. O_EXCL|O_NOFOLLOW prevents overwrite/redirection.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temporary_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(GitError::Io {
            op: "retirement_identity",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: successful openat returned a new owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    std::io::Write::write_all(&mut file, &bytes).map_err(|source| GitError::Io {
        op: "retirement_identity",
        source,
    })?;
    file.sync_all().map_err(|source| GitError::Io {
        op: "retirement_identity",
        source,
    })?;
    drop(file);
    // SAFETY: both names are in the same bound directory, so the replacement is atomic and
    // cannot be redirected through repository-controlled path components.
    let rc = unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            temporary_name.as_ptr(),
            dir.as_raw_fd(),
            final_name.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(GitError::Io {
            op: "retirement_identity",
            source: std::io::Error::last_os_error(),
        });
    }
    // Persist the directory entry as well as the identity contents.
    let directory = unsafe { std::fs::File::from_raw_fd(dir.into_raw_fd()) };
    directory.sync_all().map_err(|source| GitError::Io {
        op: "retirement_identity",
        source,
    })?;
    Ok(())
}

fn read_retirement_identity(
    dir: BorrowedFd<'_>,
    lineage: &str,
) -> Result<RetirementTicket, GitError> {
    let name = c_name(OsStr::new(&format!("{lineage}.identity")))?;
    // SAFETY: the bound directory and name are valid. O_NOFOLLOW refuses a substituted journal.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(GitError::Io {
            op: "retirement_identity",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: successful openat returned a new owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|source| GitError::Io {
        op: "retirement_identity",
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RETIREMENT_IDENTITY_BYTES {
        return Err(retirement_invalid(
            "the durable cleanup identity is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(&mut file, MAX_RETIREMENT_IDENTITY_BYTES + 1);
    std::io::Read::read_to_end(&mut bounded, &mut bytes).map_err(|source| GitError::Io {
        op: "retirement_identity",
        source,
    })?;
    if bytes.len() as u64 > MAX_RETIREMENT_IDENTITY_BYTES {
        return Err(retirement_invalid(
            "the durable cleanup identity exceeds its size limit",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        retirement_invalid(format!("the durable cleanup identity is invalid: {error}"))
    })?;
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if !matches!(version, Some(1) | Some(2)) {
        return Err(retirement_invalid(
            "the cleanup receipt is legacy or unauthenticated; request a fresh preview while the registered worktree still exists",
        ));
    }
    serde_json::from_value(value).map_err(|error| {
        retirement_invalid(format!("the durable cleanup identity is invalid: {error}"))
    })
}

async fn load_retirement_identity(
    store: &Path,
    run: &str,
    lineage: &str,
) -> Result<RetirementTicket, GitError> {
    let dir = retirement_run_dir(store, run, false).await?;
    let ticket = read_retirement_identity(dir.as_fd(), lineage)?;
    if ticket.version != RETIREMENT_RECEIPT_VERSION {
        return Err(retirement_invalid("the cleanup receipt is legacy or unauthenticated; request a fresh preview while the registered worktree still exists"));
    }
    Ok(ticket)
}

async fn load_retirement_identity_any_version(
    store: &Path,
    run: &str,
    lineage: &str,
) -> Result<RetirementTicket, GitError> {
    let dir = retirement_run_dir(store, run, false).await?;
    read_retirement_identity(dir.as_fd(), lineage)
}

/// Validate the durable handoff plan needed when the public worktree path is already absent.
/// This does not inspect the Trash item; confirmation does that under the per-worktree lock.
pub fn retirement_handoff_planned(
    store: &Path,
    repo: &Path,
    run: &str,
    lineage: &str,
) -> Result<(), GitError> {
    let dir = retirement_run_dir_sync(store, run, false)?;
    let ticket = read_retirement_identity(dir.as_fd(), lineage)?;
    if ticket.version != RETIREMENT_RECEIPT_VERSION {
        return Err(retirement_invalid("the cleanup receipt is legacy or unauthenticated; request a fresh preview while the registered worktree still exists"));
    }
    let preserved_ref = format!("refs/acp/retained/{run}/{lineage}");
    if ticket.preserved_ref != preserved_ref {
        return Err(retirement_invalid(
            "the cleanup receipt names another retained ref",
        ));
    }
    let Some(trash_path) = ticket.trash_path.as_deref() else {
        return Err(retirement_invalid(
            "the cleanup receipt has no planned recoverable Trash location",
        ));
    };
    if !trash_path.is_absolute() || !ticket.common_dir.is_absolute() {
        return Err(retirement_invalid(
            "the cleanup receipt contains a relative recovery identity",
        ));
    }
    validate_store_layout_sync(store, repo, &ticket.common_dir)?;
    validate_admin_name(&ticket.git_admin_name)?;
    let expected_quarantine = registration_recovery_path(&ticket.common_dir, run, lineage);
    if ticket.git_quarantine_path.as_deref() != Some(expected_quarantine.as_path()) {
        return Err(retirement_invalid(
            "the cleanup receipt names another Git registration recovery location",
        ));
    }
    Ok(())
}

fn validate_admin_name(name: &str) -> Result<(), GitError> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(retirement_invalid(
            "the cleanup receipt contains an invalid Git registration identity",
        ));
    }
    Ok(())
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_store_layout_sync(store: &Path, repo: &Path, common: &Path) -> Result<(), GitError> {
    let store = std::fs::canonicalize(store).map_err(|source| GitError::Io {
        op: "retirement_directory",
        source,
    })?;
    let repo = std::fs::canonicalize(repo).map_err(|source| GitError::Io {
        op: "retirement_repository",
        source,
    })?;
    let common = std::fs::canonicalize(common).map_err(|source| GitError::Io {
        op: "retirement_repository",
        source,
    })?;
    if overlaps(&store, &repo) || overlaps(&store, &common) {
        return Err(retirement_invalid("the daemon retirement state overlaps repository-controlled storage; choose a separate ACP state directory"));
    }
    Ok(())
}

async fn validate_store_layout(store: &Path, repo: &Path, common: &Path) -> Result<(), GitError> {
    validate_store_layout_sync(store, repo, common)
}

async fn common_dir(path: &Path) -> Result<PathBuf, GitError> {
    let out = git(
        "retirement_repository",
        path,
        [
            tok("rev-parse"),
            tok("--path-format=absolute"),
            tok("--git-common-dir"),
        ],
    )
    .await?;
    tokio::fs::canonicalize(PathBuf::from(trim_eol(&out.stdout())))
        .await
        .map_err(|source| GitError::Io {
            op: "retirement_repository",
            source,
        })
}

async fn git_file_identity(
    worktree: &Path,
    common: &Path,
) -> Result<(Vec<u8>, String, PathBuf, u64, u64), GitError> {
    let path = worktree.join(".git");
    let meta = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|source| GitError::Io {
            op: "retirement_identity",
            source,
        })?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return Err(retirement_invalid(
            "the registered worktree .git entry is not a regular file",
        ));
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|source| GitError::Io {
            op: "retirement_identity",
            source,
        })?;
    let line = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.trim().strip_prefix("gitdir: "))
        .ok_or_else(|| retirement_invalid("the registered worktree .git file is malformed"))?;
    let raw = PathBuf::from(line);
    let git_dir = tokio::fs::canonicalize(if raw.is_absolute() {
        raw
    } else {
        worktree.join(raw)
    })
    .await
    .map_err(|source| GitError::Io {
        op: "retirement_identity",
        source,
    })?;
    let admin = tokio::fs::metadata(&git_dir)
        .await
        .map_err(|source| GitError::Io {
            op: "retirement_identity",
            source,
        })?;
    if !admin.is_dir() {
        return Err(retirement_invalid(
            "the registered worktree Git admin entry is not a directory",
        ));
    }
    let expected_parent = tokio::fs::canonicalize(common.join("worktrees"))
        .await
        .map_err(|source| GitError::Io {
            op: "retirement_identity",
            source,
        })?;
    if git_dir.parent() != Some(expected_parent.as_path()) {
        return Err(retirement_invalid(
            "the registered Git administration path is outside the resolved common directory",
        ));
    }
    let admin_name = git_dir
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| {
            retirement_invalid("the registered Git administration identity is not valid UTF-8")
        })?
        .to_owned();
    validate_admin_name(&admin_name)?;
    Ok((bytes, admin_name, git_dir, admin.dev(), admin.ino()))
}

fn derived_git_dir(common: &Path, ticket: &RetirementTicket) -> Result<PathBuf, GitError> {
    validate_admin_name(&ticket.git_admin_name)?;
    Ok(common.join("worktrees").join(&ticket.git_admin_name))
}

async fn verify_recorded_branch(git_dir: &Path, expected_branch: &str) -> Result<(), GitError> {
    let head = tokio::fs::read(git_dir.join("HEAD"))
        .await
        .map_err(|source| GitError::Io {
            op: "retirement_identity",
            source,
        })?;
    let expected = format!("ref: refs/heads/{expected_branch}");
    if String::from_utf8_lossy(&head).trim() != expected {
        return Err(retirement_invalid(
            "the path is not the ACP worktree branch recorded for this lineage",
        ));
    }
    Ok(())
}

/// Bind a freshly created lineage to its original filesystem directory and Git registration.
/// This records identity only. The retained Git ref and Trash plan are created at retirement.
pub async fn record_original_worktree(
    repo: &Path, worktree: &Path, store: &Path, run: &str, lineage: &str,
) -> Result<(), GitError> {
    let common = common_dir(repo).await?;
    validate_store_layout(store, repo, &common).await?;
    let ticket = current_worktree_identity(worktree, common, run, lineage).await?;
    if tokio::fs::try_exists(retirement_identity(store, run, lineage)).await
        .map_err(|source| GitError::Io { op: "worktree_identity", source })? {
        return Err(retirement_invalid("this lineage already has a worktree identity"));
    }
    save_retirement_identity(store, run, lineage, &ticket).await
}

async fn current_worktree_identity(
    worktree: &Path, common: PathBuf, run: &str, lineage: &str,
) -> Result<RetirementTicket, GitError> {
    let root = tokio::fs::symlink_metadata(worktree).await
        .map_err(|source| GitError::Io { op: "worktree_identity", source })?;
    if !root.is_dir() {
        return Err(retirement_invalid("the recorded worktree is not a directory"));
    }
    let (git_file, git_admin_name, _, git_dir_dev, git_dir_ino) =
        git_file_identity(worktree, &common).await?;
    Ok(RetirementTicket {
        version: RETIREMENT_RECEIPT_VERSION,
        preserved_ref: format!("refs/acp/retained/{run}/{lineage}"),
        root_dev: root.dev(), root_ino: root.ino(), git_file, common_dir: common,
        git_admin_name, git_dir_dev, git_dir_ino,
        trash_path: None, git_quarantine_path: None, registration_retired: false,
    })
}

impl RetirementTicket {
    fn same_worktree(&self, other: &Self) -> bool {
        self.preserved_ref == other.preserved_ref
            && self.root_dev == other.root_dev && self.root_ino == other.root_ino
            && self.git_file == other.git_file && self.common_dir == other.common_dir
            && self.git_admin_name == other.git_admin_name
            && self.git_dir_dev == other.git_dir_dev && self.git_dir_ino == other.git_dir_ino
    }
}

/// A closed lineage can be collected only when the original registration is known.
/// A missing public path is handled by the journal's separate interrupted-move checks.
pub async fn verify_closed_worktree(
    repo: &Path, worktree: &Path, store: &Path, run: &str, lineage: &str,
) -> Result<(), GitError> {
    let common = common_dir(repo).await?;
    validate_store_layout(store, repo, &common).await?;
    let recorded = load_retirement_identity_any_version(store, run, lineage).await?;
    let current = current_worktree_identity(worktree, common, run, lineage).await?;
    if recorded.registration_retired || !recorded.same_worktree(&current) {
        return Err(retirement_invalid("the original worktree registration no longer matches; the current checkout was preserved"));
    }
    Ok(())
}

/// Validate exact recorded ownership and content, then preserve the integrated commit outside the
/// worktree. Nothing is removed here; the caller records retirement before using the ticket.
pub async fn prepare_retirement(
    repo: &Path,
    worktree: &Path,
    integrated_sha: &str,
    expected_branch: &str,
    store: &Path,
    run: &str,
    lineage: &str,
) -> Result<RetirementTicket, GitError> {
    prepare_retirement_with_identity(repo, worktree, integrated_sha, expected_branch,
        store, RetirementTarget::new(run, lineage), RetirementAuthorization::Human).await
}

pub(crate) async fn prepare_previewed_retirement(
    repo: &Path, worktree: &Path, sha: &str, branch: &str, store: &Path,
    target: RetirementTarget<'_>, expected: &PreviewCheckout,
) -> Result<RetirementTicket, GitError> {
    prepare_retirement_with_identity(repo, worktree, sha, branch, store, target,
        RetirementAuthorization::Preview(expected)).await
}

/// GC has no human preview to establish ownership. Require the previously recorded identity
/// inside preparation as well as during candidate selection, including after a racing removal.
pub async fn prepare_closed_retirement(
    repo: &Path, worktree: &Path, sha: &str, branch: &str, store: &Path, target: RetirementTarget<'_>,
) -> Result<RetirementTicket, GitError> {
    prepare_retirement_with_identity(repo, worktree, sha, branch, store, target, RetirementAuthorization::Recorded).await
}

enum RetirementAuthorization<'a> {
    Human,
    Recorded,
    Preview(&'a PreviewCheckout),
}

async fn prepare_retirement_with_identity(
    repo: &Path, worktree: &Path, integrated_sha: &str, expected_branch: &str,
    store: &Path, target: RetirementTarget<'_>, authorization: RetirementAuthorization<'_>,
) -> Result<RetirementTicket, GitError> {
    let RetirementTarget { run, lineage, .. } = target;
    checked_sha("prepare_retirement", integrated_sha)?;
    let prior = if matches!(authorization, RetirementAuthorization::Recorded) || tokio::fs::symlink_metadata(retirement_identity(store, run, lineage))
        .await
        .is_ok()
    {
        let durable = load_retirement_identity_any_version(store, run, lineage).await?;
        if durable.registration_retired {
            return Err(retirement_invalid(
                "this lineage already has a recoverable Trash item; the old path was reused and was preserved",
            ));
        }
        Some(durable)
    } else {
        None
    };
    let canonical_repo = tokio::fs::canonicalize(repo)
        .await
        .map_err(|source| GitError::Io {
            op: "prepare_retirement",
            source,
        })?;
    let canonical_worktree =
        tokio::fs::canonicalize(worktree)
            .await
            .map_err(|source| GitError::Io {
                op: "prepare_retirement",
                source,
            })?;
    let relative = canonical_worktree
        .strip_prefix(&canonical_repo)
        .map_err(|_| retirement_invalid("the recorded path is outside its repository"))?;
    if !relative.starts_with(Path::new(".acp/worktrees")) || relative.components().count() <= 2 {
        return Err(retirement_invalid(
            "the recorded path is not in ACP's worktree directory",
        ));
    }
    // An alternate spelling such as /var or /private/var may identify the repository.
    // Every component below that anchor must still be the recorded, unredirected suffix.
    let anchor = worktree
        .ancestors()
        .nth(relative.components().count())
        .ok_or_else(|| retirement_invalid("the recorded worktree path was redirected"))?;
    if !worktree.ends_with(relative)
        || tokio::fs::canonicalize(anchor)
            .await
            .map_err(|source| GitError::Io {
                op: "prepare_retirement",
                source,
            })?
            != canonical_repo
    {
        return Err(retirement_invalid(
            "the recorded worktree path was redirected",
        ));
    }
    let resolved_common = common_dir(repo).await?;
    validate_store_layout(store, repo, &resolved_common).await?;
    let ticket = current_worktree_identity(worktree, resolved_common.clone(), run, lineage).await?;
    if let RetirementAuthorization::Preview(expected) = authorization {
        let observed = PreviewCheckout::capture(worktree).map_err(|source|
            GitError::Io { op: "retirement_preview", source })?;
        if expected != &observed || !matches!(observed, PreviewCheckout::Present {
            root, git_file: Some(_),
        } if root == (ticket.root_dev, ticket.root_ino)) {
            return Err(retirement_invalid("the worktree registration changed after preview; request a fresh preview"));
        }
    }
    if prior.as_ref().is_some_and(|identity| !identity.same_worktree(&ticket)) {
        return Err(retirement_invalid("the recorded cleanup identity no longer matches this worktree"));
    }
    verify_recorded_branch(&derived_git_dir(&resolved_common, &ticket)?, expected_branch).await?;
    let top = tokio::fs::canonicalize(repo_root(worktree).await?)
        .await
        .map_err(|source| GitError::Io {
            op: "prepare_retirement",
            source,
        })?;
    if top != canonical_worktree || resolved_common != common_dir(worktree).await? {
        return Err(retirement_invalid(
            "the path belongs to another Git repository",
        ));
    }
    if head_sha(worktree).await? != integrated_sha {
        return Err(retirement_invalid(
            "the worktree HEAD is not the recorded integrated commit",
        ));
    }
    let branch_ref = format!("refs/heads/{expected_branch}");
    if resolve_ref(repo, &branch_ref).await? != integrated_sha {
        return Err(retirement_invalid(
            "the recorded integrated commit is not reachable from the recorded ACP branch",
        ));
    }
    let status = git(
        "retirement_status",
        worktree,
        [
            tok("status"),
            tok("--porcelain"),
            tok("-z"),
            tok("--untracked-files=all"),
            tok("--ignored=matching"),
        ],
    )
    .await?;
    if !status.into_raw().is_empty() {
        return Err(retirement_invalid(
            "the worktree has modified, untracked, or ignored content; it was preserved",
        ));
    }
    let preserved_ref = format!("refs/acp/retained/{run}/{lineage}");
    let existing = git_raw(
        "retirement_ref",
        repo,
        [
            tok("rev-parse"),
            tok("--verify"),
            tok("--end-of-options"),
            OsStr::new(&preserved_ref),
        ],
    )
    .await?;
    if existing.status.success() {
        let found = checked_sha(
            "retirement_ref",
            String::from_utf8_lossy(&existing.stdout).trim(),
        )?;
        if found != integrated_sha {
            return Err(retirement_invalid(
                "the preserved ACP ref already names another commit",
            ));
        }
    } else {
        git(
            "retirement_ref",
            repo,
            [
                tok("update-ref"),
                OsStr::new(&preserved_ref),
                OsStr::new(integrated_sha),
                OsStr::new(&"0".repeat(40)),
            ],
        )
        .await?;
    }
    let durable = if let Some(durable) = prior {
        if durable.version == RETIREMENT_RECEIPT_VERSION {
            durable
        } else {
            // A v1 plan kept the Git-registration recovery item in private state, which may be a
            // different volume. While the original registered tree is still present, the exact
            // inode/Git identities above authorize replacing only that plan with the v2
            // same-filesystem destination. Once the tree has moved, v1 remains fail-closed.
            ticket
        }
    } else {
        ticket
    };
    // The event log may only advertise a prepared retirement after the exact worktree identity is
    // durable. Persist both first-time and migrated receipts here so a crash cannot leave a
    // WorktreeRetired event whose cleanup identity never existed.
    save_retirement_identity(store, run, lineage, &durable).await?;
    Ok(durable)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementResult {
    pub preserved_ref: String,
    pub restore_path: PathBuf,
    pub disk_space_reclaimed: bool,
}

#[cfg(target_os = "macos")]
fn system_trash_destination(source: &Path, leaf: &OsStr) -> Result<PathBuf, GitError> {
    use std::ffi::{c_char, c_void, CStr};

    type Id = *mut c_void;
    type Sel = *mut c_void;
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn objc_msgSend();
    }
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {}

    unsafe fn class(name: &'static [u8]) -> Id {
        unsafe { objc_getClass(name.as_ptr().cast()) }
    }
    unsafe fn sel(name: &'static [u8]) -> Sel {
        unsafe { sel_registerName(name.as_ptr().cast()) }
    }
    unsafe fn send0(receiver: Id, selector: Sel) -> Id {
        let call: unsafe extern "C" fn(Id, Sel) -> Id =
            unsafe { std::mem::transmute(objc_msgSend as *const ()) };
        unsafe { call(receiver, selector) }
    }
    unsafe fn send_url(receiver: Id, selector: Sel, path: *const c_char, len: usize) -> Id {
        let call: unsafe extern "C" fn(Id, Sel, *const c_char, bool, Id) -> Id =
            unsafe { std::mem::transmute(objc_msgSend as *const ()) };
        unsafe { call(receiver, selector, path, len != 0, std::ptr::null_mut()) }
    }
    unsafe fn send_directory(receiver: Id, selector: Sel, appropriate: Id, error: *mut Id) -> Id {
        let call: unsafe extern "C" fn(Id, Sel, usize, usize, Id, bool, *mut Id) -> Id =
            unsafe { std::mem::transmute(objc_msgSend as *const ()) };
        // NSTrashDirectory (102), NSUserDomainMask (1). With an appropriate URL Foundation
        // returns the Trash directory on the source volume.
        unsafe { call(receiver, selector, 102, 1, appropriate, true, error) }
    }
    unsafe fn send_cstr(receiver: Id, selector: Sel) -> *const c_char {
        let call: unsafe extern "C" fn(Id, Sel) -> *const c_char =
            unsafe { std::mem::transmute(objc_msgSend as *const ()) };
        unsafe { call(receiver, selector) }
    }

    let raw = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| retirement_invalid("the worktree path contains a NUL byte"))?;
    // SAFETY: Foundation objects remain alive inside this autorelease pool and all selectors have
    // the documented signatures used below. NSURL's filesystem-representation initializer keeps
    // non-UTF-8 POSIX paths intact.
    unsafe {
        let pool = send0(class(b"NSAutoreleasePool\0"), sel(b"new\0"));
        let url_class = class(b"NSURL\0");
        let url = send_url(
            url_class,
            sel(b"fileURLWithFileSystemRepresentation:isDirectory:relativeToURL:\0"),
            raw.as_ptr(),
            raw.as_bytes().len(),
        );
        let manager = send0(class(b"NSFileManager\0"), sel(b"defaultManager\0"));
        let mut error: Id = std::ptr::null_mut();
        let trash = send_directory(
            manager,
            sel(b"URLForDirectory:inDomain:appropriateForURL:create:error:\0"),
            url,
            &mut error,
        );
        if trash.is_null() {
            let detail = if error.is_null() {
                "the system Trash service declined the move".to_string()
            } else {
                let description = send0(error, sel(b"localizedDescription\0"));
                let bytes = send_cstr(description, sel(b"UTF8String\0"));
                if bytes.is_null() {
                    "the system Trash service declined the move".to_string()
                } else {
                    CStr::from_ptr(bytes)
                        .to_string_lossy()
                        .chars()
                        .take(512)
                        .collect()
                }
            };
            let _: () = {
                let call: unsafe extern "C" fn(Id, Sel) =
                    std::mem::transmute(objc_msgSend as *const ());
                call(pool, sel(b"drain\0"));
            };
            return Err(retirement_invalid(format!(
                "the worktree was preserved because {detail}"
            )));
        }
        let bytes = send_cstr(trash, sel(b"fileSystemRepresentation\0"));
        if bytes.is_null() {
            return Err(retirement_invalid(
                "the Trash service returned no recoverable path",
            ));
        }
        let destination =
            PathBuf::from(OsStr::from_bytes(CStr::from_ptr(bytes).to_bytes())).join(leaf);
        let call: unsafe extern "C" fn(Id, Sel) = std::mem::transmute(objc_msgSend as *const ());
        call(pool, sel(b"drain\0"));
        Ok(destination)
    }
}

#[cfg(not(target_os = "macos"))]
fn system_trash_destination(_source: &Path, _leaf: &OsStr) -> Result<PathBuf, GitError> {
    Err(retirement_invalid(
        "this platform has no supported ACP Trash handoff; the worktree was preserved",
    ))
}

fn open_bound_directory(path: &Path, op: &'static str) -> Result<OwnedFd, GitError> {
    let canonical = std::fs::canonicalize(path).map_err(|source| GitError::Io { op, source })?;
    if !canonical.is_absolute() {
        return Err(retirement_invalid(
            "a retirement parent directory is not absolute",
        ));
    }
    let root = c_name(OsStr::new("/"))?;
    // SAFETY: root is NUL terminated. Opening the filesystem root gives component-by-component
    // traversal a stable anchor; every child below is opened with O_NOFOLLOW.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(GitError::Io {
            op,
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: successful open returned a new owned descriptor.
    let mut directory = unsafe { OwnedFd::from_raw_fd(fd) };
    for component in canonical.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => directory = open_dir_at(directory.as_fd(), name, false)?,
            _ => {
                return Err(retirement_invalid(
                    "a retirement parent path has an unsupported component",
                ))
            }
        }
    }
    Ok(directory)
}

fn directory_metadata_at(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    op: &'static str,
) -> Result<(OwnedFd, std::fs::Metadata), GitError> {
    let name = c_name(name)?;
    // SAFETY: parent is a bound directory and name is NUL terminated. O_NOFOLLOW and O_DIRECTORY
    // reject a symlink or non-directory source entry before the exclusive rename.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(GitError::Io {
            op,
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: successful openat returned a new owned descriptor. Metadata is read through that
    // descriptor, not by resolving the source pathname a second time.
    let directory = unsafe { OwnedFd::from_raw_fd(fd) };
    let file = std::fs::File::from(
        directory
            .try_clone()
            .map_err(|source| GitError::Io { op, source })?,
    );
    let metadata = file
        .metadata()
        .map_err(|source| GitError::Io { op, source })?;
    Ok((directory, metadata))
}

#[cfg(target_os = "macos")]
fn rename_exclusive_at(
    source_parent: BorrowedFd<'_>,
    source_name: &OsStr,
    destination_parent: BorrowedFd<'_>,
    destination_name: &OsStr,
    op: &'static str,
) -> Result<(), GitError> {
    let source_name = c_name(source_name)?;
    let destination_name = c_name(destination_name)?;
    // SAFETY: both descriptors and NUL-terminated leaf names are valid. RENAME_EXCL performs the
    // no-replace decision and rename atomically within the kernel.
    let rc = unsafe {
        libc::renameatx_np(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(GitError::Io {
            op,
            source: std::io::Error::last_os_error(),
        })
    }
}

#[cfg(not(target_os = "macos"))]
fn rename_exclusive_at(
    _source_parent: BorrowedFd<'_>,
    _source_name: &OsStr,
    _destination_parent: BorrowedFd<'_>,
    _destination_name: &OsStr,
    _op: &'static str,
) -> Result<(), GitError> {
    Err(retirement_invalid(
        "this platform has no supported descriptor-relative no-replace rename; content was preserved",
    ))
}

fn sync_directory(directory: BorrowedFd<'_>, op: &'static str) -> Result<(), GitError> {
    std::fs::File::from(
        directory
            .try_clone_to_owned()
            .map_err(|source| GitError::Io { op, source })?,
    )
    .sync_all()
    .map_err(|source| GitError::Io { op, source })
}

fn identity_mismatch_after_move(
    source_parent: BorrowedFd<'_>,
    source_name: &OsStr,
    destination_parent: BorrowedFd<'_>,
    destination_name: &OsStr,
    source: &Path,
    destination: &Path,
    op: &'static str,
) -> GitError {
    match rename_exclusive_at(
        destination_parent,
        destination_name,
        source_parent,
        source_name,
        op,
    ) {
        Ok(()) => {
            let durability = sync_directory(source_parent, op)
                .and_then(|()| sync_directory(destination_parent, op));
            retirement_invalid(if let Err(error) = durability {
                format!(
                    "the source leaf changed during retirement; the moved directory was restored without overwrite at {}, but synchronizing its parent failed ({error}); preserve that exact path",
                    source.display(),
                )
            } else {
                format!(
                    "the source leaf changed during retirement; the moved directory was restored without overwrite at {}",
                    source.display(),
                )
            })
        }
        Err(error) => retirement_invalid(format!(
            "the source leaf changed during retirement and safe restoration failed ({error}); preserve and recover the moved directory at {}",
            destination.display(),
        )),
    }
}

fn move_directory_no_replace(
    source: &Path,
    destination_parent: BorrowedFd<'_>,
    destination_parent_path: &Path,
    destination_name: &OsStr,
    expected_dev: u64,
    expected_ino: u64,
    op: &'static str,
) -> Result<(), GitError> {
    let source_parent_path = source
        .parent()
        .ok_or_else(|| retirement_invalid("the retirement source has no parent"))?;
    let source_name = source
        .file_name()
        .ok_or_else(|| retirement_invalid("the retirement source has no name"))?;
    let source_parent = open_bound_directory(source_parent_path, op)?;
    let destination_parent_file = std::fs::File::from(
        destination_parent
            .try_clone_to_owned()
            .map_err(|source| GitError::Io { op, source })?,
    );
    let destination_parent_meta = destination_parent_file
        .metadata()
        .map_err(|source| GitError::Io { op, source })?;
    let (_source_entry, source_meta) =
        directory_metadata_at(source_parent.as_fd(), source_name, op)?;
    if source_meta.dev() != expected_dev || source_meta.ino() != expected_ino {
        return Err(retirement_invalid(
            "the descriptor-bound retirement source has the wrong identity; it was preserved",
        ));
    }
    if source_meta.dev() != destination_parent_meta.dev() {
        return Err(retirement_invalid(
            "the retirement destination is not on the source filesystem",
        ));
    }
    rename_exclusive_at(
        source_parent.as_fd(),
        source_name,
        destination_parent,
        destination_name,
        op,
    )?;
    let destination = destination_parent_path.join(destination_name);
    let moved = directory_metadata_at(destination_parent, destination_name, op);
    let identity_matches = moved.as_ref().is_ok_and(|(_, metadata)| {
        metadata.dev() == expected_dev && metadata.ino() == expected_ino
    });
    if !identity_matches {
        return Err(identity_mismatch_after_move(
            source_parent.as_fd(),
            source_name,
            destination_parent,
            destination_name,
            source,
            &destination,
            op,
        ));
    }
    sync_directory(source_parent.as_fd(), op)?;
    Ok(())
}

fn move_to_fixture_trash(
    source: &Path,
    destination: &Path,
    expected_dev: u64,
    expected_ino: u64,
) -> Result<(), GitError> {
    let destination_parent_path = destination
        .parent()
        .ok_or_else(|| retirement_invalid("the Trash destination has no parent"))?;
    let destination_name = destination
        .file_name()
        .ok_or_else(|| retirement_invalid("the Trash destination has no name"))?;
    let destination_parent = open_bound_directory(destination_parent_path, "retirement_trash")?;
    move_directory_no_replace(
        source,
        destination_parent.as_fd(),
        destination_parent_path,
        destination_name,
        expected_dev,
        expected_ino,
        "retirement_trash",
    )?;
    sync_directory(destination_parent.as_fd(), "retirement_trash")
}

fn move_registration_to_journal(
    source: &Path,
    journal: BorrowedFd<'_>,
    journal_path: &Path,
    destination_name: &OsStr,
    expected_dev: u64,
    expected_ino: u64,
) -> Result<(), GitError> {
    move_directory_no_replace(
        source,
        journal,
        journal_path,
        destination_name,
        expected_dev,
        expected_ino,
        "retirement_deregister",
    )
}

#[cfg(debug_assertions)]
fn injected_trash_destination() -> Option<PathBuf> {
    std::env::var_os("ACP_FAKE_RETIREMENT_TRASH_DESTINATION").map(PathBuf::from)
}

#[cfg(not(debug_assertions))]
fn injected_trash_destination() -> Option<PathBuf> {
    None
}

/// Hand the validated tree to the platform Trash, retain its exact identity for recovery, and
/// remove only that now-absent worktree's Git registration. File contents are never unlinked here.
pub struct RetirementTarget<'a> {
    pub run: &'a str,
    pub lineage: &'a str,
    fixture_trash: Option<&'a Path>,
}

impl<'a> RetirementTarget<'a> {
    pub fn new(run: &'a str, lineage: &'a str) -> Self {
        Self {
            run,
            lineage,
            fixture_trash: None,
        }
    }
}

pub async fn quarantine_and_remove_worktree(
    repo: &Path,
    worktree: &Path,
    integrated_sha: &str,
    store: &Path,
    expected_branch: &str,
    target: RetirementTarget<'_>,
    ticket: Option<RetirementTicket>,
) -> Result<RetirementResult, GitError> {
    let RetirementTarget {
        run,
        lineage,
        fixture_trash,
    } = target;
    checked_sha("retirement_remove", integrated_sha)?;
    let resolved_common = common_dir(repo).await?;
    validate_store_layout(store, repo, &resolved_common).await?;
    let public_exists = tokio::fs::symlink_metadata(worktree).await.is_ok();
    if public_exists {
        let mut ticket = ticket
            .ok_or_else(|| retirement_invalid("cleanup lost its validated filesystem identity"))?;
        let meta = tokio::fs::metadata(worktree)
            .await
            .map_err(|source| GitError::Io {
                op: "retirement_identity",
                source,
            })?;
        let (git_file, admin_name, git_dir, git_dev, git_ino) =
            git_file_identity(worktree, &resolved_common).await?;
        if meta.dev() != ticket.root_dev
            || meta.ino() != ticket.root_ino
            || git_file != ticket.git_file
            || resolved_common != ticket.common_dir
            || admin_name != ticket.git_admin_name
            || git_dir != derived_git_dir(&resolved_common, &ticket)?
            || git_dev != ticket.git_dir_dev
            || git_ino != ticket.git_dir_ino
        {
            return Err(retirement_invalid(
                "the validated worktree path was substituted before cleanup",
            ));
        }
        verify_recorded_branch(&git_dir, expected_branch).await?;
        let status = git(
            "retirement_recheck",
            worktree,
            [
                tok("status"),
                tok("--porcelain"),
                tok("-z"),
                tok("--untracked-files=all"),
                tok("--ignored=matching"),
            ],
        )
        .await?;
        if !status.into_raw().is_empty() {
            return Err(retirement_invalid(
                "content changed after retirement validation; the worktree was preserved",
            ));
        }
        if ticket.registration_retired {
            return Err(retirement_invalid(
                "the recorded path was reused after its ACP tree moved to Trash",
            ));
        }
        if ticket.trash_path.is_none() {
            let injected = injected_trash_destination();
            let fixture_trash = fixture_trash.or(injected.as_deref());
            let leaf = format!(
                "acp-{run}-{lineage}-{}-{}",
                ticket.root_dev, ticket.root_ino
            );
            ticket.trash_path = Some(if let Some(destination) = fixture_trash {
                destination.to_path_buf()
            } else {
                system_trash_destination(worktree, OsStr::new(&leaf))?
            });
            ticket.git_quarantine_path =
                Some(registration_recovery_path(&resolved_common, run, lineage));
        }
        // Both recovery locations and the bound identities are durable before either directory
        // moves. A restart can therefore find the tree even if the process dies on the next line.
        save_retirement_identity(store, run, lineage, &ticket).await?;
        let destination = ticket
            .trash_path
            .clone()
            .expect("planned Trash destination");
        move_to_fixture_trash(worktree, &destination, ticket.root_dev, ticket.root_ino)?;
        let moved = tokio::fs::metadata(&destination)
            .await
            .map_err(|source| GitError::Io {
                op: "retirement_identity",
                source,
            })?;
        let (moved_file, moved_admin_name, moved_dir, moved_dev, moved_ino) =
            git_file_identity(&destination, &resolved_common).await?;
        if moved.dev() != ticket.root_dev
            || moved.ino() != ticket.root_ino
            || moved_file != ticket.git_file
            || moved_admin_name != ticket.git_admin_name
            || moved_dir != derived_git_dir(&resolved_common, &ticket)?
            || moved_dev != ticket.git_dir_dev
            || moved_ino != ticket.git_dir_ino
        {
            return Err(retirement_invalid(
                "the Trash item is not the worktree that was validated; it was preserved",
            ));
        }
    }

    let mut durable = load_retirement_identity(store, run, lineage).await?;
    if durable.common_dir != resolved_common {
        return Err(retirement_invalid(
            "the cleanup receipt belongs to another Git common directory",
        ));
    }
    let git_dir = derived_git_dir(&resolved_common, &durable)?;
    let destination = durable.trash_path.clone().ok_or_else(|| retirement_invalid(
        "cleanup stopped before the recoverable Trash location was recorded; the tree was preserved",
    ))?;
    if tokio::fs::symlink_metadata(worktree).await.is_ok() {
        return Err(retirement_invalid(
            "the retired path has been reused; no new tree was inspected or removed",
        ));
    }
    let root = match tokio::fs::symlink_metadata(&destination).await {
        Ok(root) => root,
        Err(source)
            if source.kind() == std::io::ErrorKind::NotFound && durable.registration_retired =>
        {
            let found = resolve_ref(repo, &durable.preserved_ref).await?;
            if found != integrated_sha {
                return Err(retirement_invalid(
                    "the retained ACP ref no longer names the integrated commit",
                ));
            }
            return Ok(RetirementResult {
                preserved_ref: durable.preserved_ref,
                restore_path: destination,
                disk_space_reclaimed: true,
            });
        }
        Err(source) => {
            return Err(GitError::Io {
                op: "retirement_identity",
                source,
            })
        }
    };
    if !root.file_type().is_dir()
        || root.file_type().is_symlink()
        || root.dev() != durable.root_dev
        || root.ino() != durable.root_ino
    {
        return Err(retirement_invalid(
            "the recorded Trash item is unavailable or was substituted",
        ));
    }
    let gitfile = tokio::fs::symlink_metadata(destination.join(".git"))
        .await
        .map_err(|source| GitError::Io {
            op: "retirement_identity",
            source,
        })?;
    if !gitfile.file_type().is_file()
        || gitfile.file_type().is_symlink()
        || tokio::fs::read(destination.join(".git"))
            .await
            .map_err(|source| GitError::Io {
                op: "retirement_identity",
                source,
            })?
            != durable.git_file
    {
        return Err(retirement_invalid(
            "the recorded Trash item's Git identity changed",
        ));
    }
    let found = resolve_ref(repo, &durable.preserved_ref).await?;
    if found != integrated_sha {
        return Err(retirement_invalid(
            "the retained ACP ref no longer names the integrated commit",
        ));
    }
    let quarantine = durable.git_quarantine_path.clone().ok_or_else(|| {
        retirement_invalid(
            "cleanup stopped before the Git registration recovery location was recorded",
        )
    })?;
    let expected_quarantine = registration_recovery_path(&resolved_common, run, lineage);
    if quarantine != expected_quarantine {
        return Err(retirement_invalid(
            "the Git registration recovery location is inconsistent",
        ));
    }
    if !durable.registration_retired {
        if tokio::fs::symlink_metadata(&git_dir).await.is_ok() {
            let admin = tokio::fs::metadata(&git_dir)
                .await
                .map_err(|source| GitError::Io {
                    op: "retirement_deregister",
                    source,
                })?;
            if admin.dev() != durable.git_dir_dev || admin.ino() != durable.git_dir_ino {
                return Err(retirement_invalid(
                    "the Git registration was substituted; it was preserved",
                ));
            }
            if tokio::fs::symlink_metadata(worktree).await.is_ok() {
                return Err(retirement_invalid(
                    "the retired path was reused; its registration was preserved",
                ));
            }
            // Git registration metadata may be on a different volume from private ACP state.
            // Keep its recovery directory beside the common Git directory (but outside Git's
            // `worktrees` registrations) so the no-replace rename remains atomic.
            let journal = registration_run_dir(&resolved_common, run, true).await?;
            let quarantine_name = quarantine.file_name().ok_or_else(|| {
                retirement_invalid("the Git registration recovery path has no name")
            })?;
            move_registration_to_journal(
                &git_dir,
                journal.as_fd(),
                quarantine
                    .parent()
                    .expect("retirement quarantine has a parent"),
                quarantine_name,
                durable.git_dir_dev,
                durable.git_dir_ino,
            )?;
            std::fs::File::from(journal)
                .sync_all()
                .map_err(|source| GitError::Io {
                    op: "retirement_deregister",
                    source,
                })?;
        }
        let quarantined =
            tokio::fs::metadata(&quarantine)
                .await
                .map_err(|source| GitError::Io {
                    op: "retirement_deregister",
                    source,
                })?;
        if quarantined.dev() != durable.git_dir_dev || quarantined.ino() != durable.git_dir_ino {
            return Err(retirement_invalid(
                "the quarantined Git registration has the wrong identity",
            ));
        }
        durable.registration_retired = true;
        save_retirement_identity(store, run, lineage, &durable).await?;
    }
    if tokio::fs::symlink_metadata(&git_dir).await.is_ok() {
        return Err(retirement_invalid(
            "the target Git registration still exists",
        ));
    }
    Ok(RetirementResult {
        preserved_ref: durable.preserved_ref,
        restore_path: destination,
        disk_space_reclaimed: false,
    })
}

pub fn retirement_identity_path(store: &Path, run: &str, lineage: &str) -> PathBuf {
    retirement_identity(store, run, lineage)
}

/// A completed handoff has a recorded recovery path and no remaining selected Git administration
/// directory. This bounded journal read lets ordinary GC keep its historical "nothing left" result
/// without using repository-wide prune or inspecting the Trash item.
pub fn retirement_complete(store: &Path, repo: &Path, run: &str, lineage: &str) -> bool {
    if retirement_handoff_planned(store, repo, run, lineage).is_err() {
        return false;
    }
    let Ok(dir) = retirement_run_dir_sync(store, run, false) else {
        return false;
    };
    let Ok(ticket) = read_retirement_identity(dir.as_fd(), lineage) else {
        return false;
    };
    let Ok(git_dir) = derived_git_dir(&ticket.common_dir, &ticket) else {
        return false;
    };
    ticket.version == RETIREMENT_RECEIPT_VERSION
        && ticket.registration_retired
        && std::fs::symlink_metadata(git_dir).is_err()
}

/// Create `path` as a new worktree of `repo` on a new branch `branch`, checked out at `base_sha`.
pub async fn add_worktree(
    repo: &Path,
    path: &Path,
    branch: &str,
    base_sha: &str,
) -> Result<(), GitError> {
    checked_sha("add_worktree", base_sha)?;
    git(
        "add_worktree",
        repo,
        [
            tok("worktree"),
            tok("add"),
            tok("-b"),
            OsStr::new(branch),
            tok("--end-of-options"),
            path.as_os_str(),
            OsStr::new(base_sha),
        ],
    )
    .await?;
    Ok(())
}

/// Detach `path` from `repo`. `force` also discards uncommitted changes in that worktree.
pub async fn remove_worktree(repo: &Path, path: &Path, force: bool) -> Result<(), GitError> {
    let mut args = vec![tok("worktree"), tok("remove")];
    if force {
        args.push(tok("--force"));
    }
    args.push(tok("--end-of-options"));
    args.push(path.as_os_str());
    git("remove_worktree", repo, args).await?;
    Ok(())
}

/// The commit `wt`'s HEAD currently points at.
pub async fn head_sha(wt: &Path) -> Result<String, GitError> {
    let out = git("head_sha", wt, [tok("rev-parse"), tok("HEAD")]).await?;
    checked_sha("head_sha", out.stdout().trim())
}

/// Raw `git status --porcelain` text, verbatim — this is what the retry prompt shows the worker.
pub async fn status_porcelain(wt: &Path) -> Result<String, GitError> {
    let out = git("status_porcelain", wt, [tok("status"), tok("--porcelain")]).await?;
    Ok(out.into_stdout())
}

/// Hash the actual checkout used by a host verification.
///
/// Entries use deterministic byte-sorted directory order and include the checkout root, every
/// directory and every ordinary file, whether tracked, ignored or untracked, plus sorted deletion
/// markers from the index. Each entry binds the raw relative name, kind, permission bits and
/// complete content. The actual tree is discovered by one descriptor-relative walk; Git supplies
/// only index-only facts such as tracked deletions and gitlinks. Reads never follow symlinks, and a
/// symlink's own target bytes are inventory data. Git administrative metadata is excluded only at
/// each known repository root. Counts, depth, individual files and aggregate input are bounded so
/// capture cannot become an unbounded read.
pub async fn source_inventory_hash(wt: &Path) -> Result<String, GitError> {
    source_inventory_hash_with_limits(wt, MAX_SOURCE_INVENTORY_PATHS, MAX_SOURCE_INVENTORY_BYTES)
        .await
}

async fn source_inventory_hash_with_limits(
    wt: &Path,
    path_limit: usize,
    byte_limit: usize,
) -> Result<String, GitError> {
    let top = tokio::fs::canonicalize(wt)
        .await
        .map_err(|source| GitError::Io {
            op: "source_inventory",
            source,
        })?;
    let mut state = InventoryState {
        digest: Sha256::new(),
        bytes_left: byte_limit,
        paths_left: path_limit,
        top: top.clone(),
        visited: HashSet::from([top.clone()]),
    };
    // v5 adds directories and their permission bits. Older reports remain readable in history but
    // cannot retain authority over source inputs their inventory domain omitted.
    state.digest.update(b"acp-source-inventory-v5\0");
    let root = open_root_dir(&top).map_err(|source| GitError::Io {
        op: "source_inventory",
        source,
    })?;
    inventory_repository(&top, root, Vec::new(), 0, true, &mut state).await?;
    Ok(format!("{:x}", state.digest.finalize()))
}

struct InventoryState {
    digest: Sha256,
    bytes_left: usize,
    paths_left: usize,
    top: PathBuf,
    visited: HashSet<PathBuf>,
}

type InventoryFuture<'a> = Pin<Box<dyn Future<Output = Result<(), GitError>> + Send + 'a>>;
#[derive(Clone)]
struct IndexEntry {
    mode: Vec<u8>,
    oid: Vec<u8>,
}

#[derive(Clone, Copy)]
struct InventoryDepth {
    directory: usize,
    submodule: usize,
}

fn inventory_repository<'a>(
    wt: &'a Path,
    root: OwnedFd,
    prefix: Vec<u8>,
    submodule_depth: usize,
    record_root: bool,
    state: &'a mut InventoryState,
) -> InventoryFuture<'a> {
    Box::pin(async move {
        let tracked = git_stdout_capped(
            "source_inventory",
            wt,
            [tok("ls-files"), tok("--cached"), tok("--stage"), tok("-z")],
            MAX_SOURCE_INVENTORY_LIST_BYTES,
        )
        .await?;
        let (tracked, tracked_truncated) = tracked.into_raw();
        if tracked_truncated {
            return Err(GitError::Io {
                op: "source_inventory",
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("source path listing exceeds {MAX_SOURCE_INVENTORY_LIST_BYTES} bytes"),
                ),
            });
        }

        // Bound index-path retention independently at ingestion. This is an allocation guard,
        // not inventory accounting: paths also found by the descriptor walk are charged there,
        // while entries left in this map are charged once as deletions below.
        let mut index_paths_left = state.paths_left;
        let mut index_bytes_left = state.bytes_left;
        let mut index = BTreeMap::new();
        for field in tracked.split(|byte| *byte == 0).filter(|f| !f.is_empty()) {
            let Some(tab) = field.iter().position(|byte| *byte == b'\t') else {
                return Err(GitError::Io {
                    op: "source_inventory",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "malformed git index entry",
                    ),
                });
            };
            let header = &field[..tab];
            let mut parts = header.split(|byte| *byte == b' ');
            let mode = parts.next().unwrap_or_default();
            let oid = parts.next().unwrap_or_default();
            let stage = parts.next().unwrap_or_default();
            let path = &field[tab + 1..];
            if mode.is_empty() || oid.len() != 40 || stage != b"0" || path.is_empty() {
                return Err(GitError::Io {
                    op: "source_inventory",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "malformed git index identity",
                    ),
                });
            }
            if index.contains_key(path) {
                return Err(inventory_invalid(
                    "source inventory contains duplicate index paths".into(),
                ));
            }
            reserve_pending_path(
                prefix.len() + path.len(),
                &mut index_paths_left,
                &mut index_bytes_left,
            )?;
            index.insert(
                path.to_vec(),
                IndexEntry {
                    mode: mode.to_vec(),
                    oid: oid.to_vec(),
                },
            );
        }

        if record_root {
            state.reserve_path(prefix.len())?;
            let metadata =
                std::fs::File::from(root.try_clone().map_err(|source| GitError::Io {
                    op: "source_inventory",
                    source,
                })?)
                .metadata()
                .map_err(|source| GitError::Io {
                    op: "source_inventory",
                    source,
                })?;
            inventory_entry(&prefix, b"directory", metadata.permissions().mode(), state);
        }
        inventory_directory(
            wt,
            root,
            Vec::new(),
            prefix.clone(),
            InventoryDepth {
                directory: 0,
                submodule: submodule_depth,
            },
            &mut index,
            state,
        )
        .await?;

        for (path, entry) in index {
            state.reserve_path(prefix.len() + path.len())?;
            let inventory_path = prefixed_path(&prefix, &path);
            if entry.mode == b"160000" {
                inventory_entry(&inventory_path, b"gitlink-missing", 0, state);
                state.digest.update(&entry.oid);
                state.digest.update(b"\0");
            } else {
                inventory_entry(&inventory_path, b"deleted", 0, state);
                state.digest.update(&entry.mode);
                state.digest.update(b"\0");
            }
        }
        Ok(())
    })
}

fn inventory_directory<'a>(
    wt: &'a Path,
    directory: OwnedFd,
    relative: Vec<u8>,
    prefix: Vec<u8>,
    depth: InventoryDepth,
    index: &'a mut BTreeMap<Vec<u8>, IndexEntry>,
    state: &'a mut InventoryState,
) -> InventoryFuture<'a> {
    Box::pin(async move {
        if depth.directory >= MAX_SOURCE_INVENTORY_DIRECTORY_DEPTH {
            return Err(inventory_invalid(format!(
                "source inventory exceeds directory depth {MAX_SOURCE_INVENTORY_DIRECTORY_DEPTH}"
            )));
        }
        let path_prefix_len = prefix.len() + relative.len() + usize::from(!relative.is_empty());
        let names =
            inventory_directory_names(&directory, relative.is_empty(), path_prefix_len, state)?;
        for name in names {
            let path = joined_path(&relative, &name);
            let inventory_path = prefixed_path(&prefix, &path);
            let opened = open_inventory_entry(directory.as_fd(), &name);
            match opened {
                Ok((file, metadata)) if metadata.is_file() => {
                    if index
                        .get(&path)
                        .is_some_and(|entry| entry.mode == b"160000")
                    {
                        return Err(inventory_invalid(format!(
                            "tracked gitlink {:?} is not a directory",
                            String::from_utf8_lossy(&path)
                        )));
                    }
                    index.remove(&path);
                    if metadata.len() > MAX_SOURCE_INVENTORY_FILE_BYTES as u64 {
                        return Err(inventory_invalid(format!(
                            "source file {:?} exceeds {MAX_SOURCE_INVENTORY_FILE_BYTES} bytes",
                            String::from_utf8_lossy(&path)
                        )));
                    }
                    inventory_entry(
                        &inventory_path,
                        b"file",
                        metadata.permissions().mode(),
                        state,
                    );
                    let (bytes, truncated) = read_capped(file, MAX_SOURCE_INVENTORY_FILE_BYTES)
                        .await
                        .map_err(|source| GitError::Io {
                            op: "source_inventory",
                            source,
                        })?;
                    if truncated {
                        return Err(inventory_too_large());
                    }
                    inventory_bytes(&bytes, state)?;
                }
                Ok((file, metadata)) if metadata.is_dir() => {
                    let child = OwnedFd::from(file);
                    if let Some(entry) = index.remove(&path) {
                        if entry.mode != b"160000" {
                            return Err(inventory_invalid(format!(
                                "tracked file {:?} became a directory",
                                String::from_utf8_lossy(&path)
                            )));
                        }
                        if depth.submodule >= MAX_SOURCE_INVENTORY_SUBMODULE_DEPTH {
                            return Err(inventory_invalid(format!(
                                "source inventory exceeds submodule depth {MAX_SOURCE_INVENTORY_SUBMODULE_DEPTH}"
                            )));
                        }
                        let subroot = tokio::fs::canonicalize(wt.join(OsStr::from_bytes(&path)))
                            .await
                            .map_err(|source| GitError::Io {
                                op: "source_inventory",
                                source,
                            })?;
                        if !subroot.starts_with(&state.top)
                            || !state.visited.insert(subroot.clone())
                        {
                            return Err(inventory_invalid(format!(
                                "tracked submodule {:?} escapes or cycles within the source root",
                                String::from_utf8_lossy(&path)
                            )));
                        }
                        let repository_root = git(
                            "source_inventory",
                            &subroot,
                            [tok("rev-parse"), tok("--show-toplevel")],
                        )
                        .await
                        .map_err(|_| {
                            inventory_invalid(format!(
                                "tracked submodule {:?} is present but uninitialized",
                                String::from_utf8_lossy(&path)
                            ))
                        })?;
                        let repository_root =
                            tokio::fs::canonicalize(repository_root.stdout().trim())
                                .await
                                .map_err(|_| {
                                    inventory_invalid(format!(
                                        "tracked submodule {:?} is present but uninitialized",
                                        String::from_utf8_lossy(&path)
                                    ))
                                })?;
                        if repository_root != subroot {
                            return Err(inventory_invalid(format!(
                                "tracked submodule {:?} is present but uninitialized",
                                String::from_utf8_lossy(&path)
                            )));
                        }
                        let checked_out = head_sha(&subroot).await.map_err(|_| {
                            inventory_invalid(format!(
                                "tracked submodule {:?} is present but uninitialized",
                                String::from_utf8_lossy(&path)
                            ))
                        })?;
                        inventory_entry(
                            &inventory_path,
                            b"gitlink",
                            metadata.permissions().mode(),
                            state,
                        );
                        state.digest.update(&entry.oid);
                        state.digest.update(b"\0");
                        state.digest.update(checked_out.as_bytes());
                        state.digest.update(b"\0");
                        let mut subprefix = inventory_path;
                        subprefix.push(b'/');
                        inventory_repository(
                            &subroot,
                            child,
                            subprefix,
                            depth.submodule + 1,
                            false,
                            state,
                        )
                        .await?;
                    } else {
                        inventory_entry(
                            &inventory_path,
                            b"directory",
                            metadata.permissions().mode(),
                            state,
                        );
                        inventory_directory(
                            wt,
                            child,
                            path,
                            prefix.clone(),
                            InventoryDepth {
                                directory: depth.directory + 1,
                                ..depth
                            },
                            index,
                            state,
                        )
                        .await?;
                    }
                }
                Ok((_file, _metadata)) => {
                    return Err(inventory_invalid(format!(
                        "source inventory refuses special file {:?}",
                        String::from_utf8_lossy(&path)
                    )));
                }
                Err(source) if source.raw_os_error() == Some(libc::ELOOP) => {
                    if index
                        .get(&path)
                        .is_some_and(|entry| entry.mode == b"160000")
                    {
                        return Err(inventory_invalid(format!(
                            "tracked gitlink {:?} is a symlink",
                            String::from_utf8_lossy(&path)
                        )));
                    }
                    index.remove(&path);
                    let target = readlink_at_name(directory.as_fd(), &name).map_err(|source| {
                        GitError::Io {
                            op: "source_inventory",
                            source,
                        }
                    })?;
                    inventory_entry(&inventory_path, b"symlink", 0o777, state);
                    inventory_bytes(&target, state)?;
                }
                Err(source) => {
                    return Err(GitError::Io {
                        op: "source_inventory",
                        source,
                    })
                }
            }
        }
        Ok(())
    })
}

fn inventory_directory_names(
    directory: &OwnedFd,
    repository_root: bool,
    path_prefix_len: usize,
    state: &mut InventoryState,
) -> Result<Vec<Vec<u8>>, GitError> {
    let descriptor = directory.try_clone().map_err(|source| GitError::Io {
        op: "source_inventory",
        source,
    })?;
    let entries =
        nix::dir::Dir::from(std::fs::File::from(descriptor)).map_err(|source| GitError::Io {
            op: "source_inventory",
            source: source.into(),
        })?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| GitError::Io {
            op: "source_inventory",
            source: source.into(),
        })?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." || (repository_root && name == b".git") {
            continue;
        }
        if name == b".git" {
            return Err(inventory_invalid(
                "unsupported nested repository metadata".into(),
            ));
        }
        // Charge each complete path before retaining its name. Siblings still waiting
        // for sorting or traversal share the same budget as nested and submodule entries.
        state.reserve_path(path_prefix_len + name.len())?;
        names.push(name.to_vec());
    }
    names.sort();
    Ok(names)
}

fn open_inventory_entry(
    directory: BorrowedFd<'_>,
    name: &[u8],
) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let name = CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    Ok((file, metadata))
}

fn readlink_at_name(directory: BorrowedFd<'_>, name: &[u8]) -> std::io::Result<Vec<u8>> {
    let name = CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut bytes = vec![0u8; MAX_SOURCE_INVENTORY_FILE_BYTES + 1];
    let length = unsafe {
        libc::readlinkat(
            directory.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let length =
        usize::try_from(length).map_err(|_| std::io::Error::other("negative link length"))?;
    if length > MAX_SOURCE_INVENTORY_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "symlink target exceeds inventory bound",
        ));
    }
    bytes.truncate(length);
    Ok(bytes)
}

fn joined_path(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = parent.to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

fn prefixed_path(prefix: &[u8], path: &[u8]) -> Vec<u8> {
    let mut full = prefix.to_vec();
    full.extend_from_slice(path);
    full
}

fn inventory_entry(path: &[u8], kind: &[u8], mode: u32, state: &mut InventoryState) {
    state.digest.update((path.len() as u64).to_be_bytes());
    state.digest.update(path);
    state.digest.update(kind);
    state.digest.update(b"\0");
    state
        .digest
        .update(format!("{:03o}", mode & 0o777).as_bytes());
    state.digest.update(b"\0");
}

fn inventory_bytes(bytes: &[u8], state: &mut InventoryState) -> Result<(), GitError> {
    state.reserve_bytes(bytes.len())?;
    state.digest.update((bytes.len() as u64).to_be_bytes());
    state.digest.update(bytes);
    Ok(())
}

/// Reserve an index path before retaining any bytes from its record. This guard mirrors the
/// inventory ceilings but deliberately does not mutate [`InventoryState`]: the descriptor walk
/// accounts paths present in the checkout, and the remaining map accounts deletions exactly once.
fn reserve_pending_path(
    bytes: usize,
    paths_left: &mut usize,
    bytes_left: &mut usize,
) -> Result<(), GitError> {
    *paths_left = paths_left.checked_sub(1).ok_or_else(|| {
        inventory_invalid("source inventory exceeds the path count limit".into())
    })?;
    *bytes_left = bytes_left.checked_sub(bytes).ok_or_else(inventory_too_large)?;
    Ok(())
}

impl InventoryState {
    fn reserve_path(&mut self, bytes: usize) -> Result<(), GitError> {
        self.paths_left = self.paths_left.checked_sub(1).ok_or_else(|| {
            inventory_invalid("source inventory exceeds the path count limit".into())
        })?;
        self.reserve_bytes(bytes)
    }

    fn reserve_bytes(&mut self, bytes: usize) -> Result<(), GitError> {
        self.bytes_left = self
            .bytes_left
            .checked_sub(bytes)
            .ok_or_else(inventory_too_large)?;
        Ok(())
    }
}

fn inventory_too_large() -> GitError {
    GitError::Io {
        op: "source_inventory",
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("source inventory exceeds {MAX_SOURCE_INVENTORY_BYTES} bytes"),
        ),
    }
}

fn inventory_invalid(message: String) -> GitError {
    GitError::Io {
        op: "source_inventory",
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, message),
    }
}

/// Every path that differs from HEAD in `wt`, including untracked ones.
///
/// `--untracked-files=all` is deliberate: plain `--porcelain` collapses an untracked directory to
/// `Sub/`, which would hide `Sub/App.xcconfig` from `match_denylist`. `-z` output is NUL-separated
/// and a rename/copy entry is followed by a second field holding the origin path, which is consumed
/// and dropped here (the new path is the one the denylist and the reviewer care about).
pub async fn changed_files(wt: &Path) -> Result<Vec<ChangedFile>, GitError> {
    let out = git(
        "changed_files",
        wt,
        [
            tok("status"),
            tok("--porcelain"),
            tok("-z"),
            tok("--untracked-files=all"),
        ],
    )
    .await?;

    let mut files = Vec::new();
    let stdout = out.stdout();
    let mut fields = stdout.split('\0');
    while let Some(entry) = fields.next() {
        if entry.len() < 4 || !entry.is_char_boundary(2) {
            continue; // trailing empty field, or a field too short to be "XY <path>"
        }
        let (status, rest) = entry.split_at(2);
        let path = rest.strip_prefix(' ').unwrap_or(rest);
        if status.starts_with(['R', 'C']) || status[1..].starts_with(['R', 'C']) {
            let _origin = fields.next(); // rename/copy source path, not reported
        }
        files.push(ChangedFile {
            path: path.to_string(),
            status: status.to_string(),
        });
    }
    Ok(files)
}

/// Write the reviewer's frozen diff to `out` and report what it contains.
///
/// `git diff HEAD` covers staged and unstaged changes to tracked files; untracked files are not in
/// it, so their bodies are appended as synthetic "new file" sections (git itself would need either
/// an index mutation via `add -N` or one `diff --no-index` child per file — neither is acceptable
/// inside a worker's worktree). A file larger than `MAX_UNTRACKED_DIFF_BYTES` is truncated and a
/// binary one is summarized, so one stray artifact cannot produce a gigabyte of patch.
///
/// **This function is the one place where the privileged daemon reads worker-chosen paths, so it
/// never follows a link out of the sandbox.** The worktree root is opened once as a directory fd
/// and every untracked file is read through [`open_under_root`], which walks the path one component
/// at a time with `openat(…, O_NOFOLLOW)`. There is no re-open by path anywhere on the read route,
/// so a worker cannot swap a *parent directory* for a symlink between the check and the read — the
/// checked directory fd is the one that is used. Anything refused is named in the diff — a symlink
/// by its target string only — and listed in [`DiffStat::symlinks`]. Without this a worker could
/// drop `link -> ~/.codex/auth.json` in its worktree and have the control plane copy the secret
/// into the reviewer prompt and the gate payload, defeating the kernel sandbox (V4).
pub async fn frozen_diff(wt: &Path, out: &Path) -> Result<DiffStat, GitError> {
    let changed = changed_files(wt).await?;
    let root = tokio::fs::canonicalize(wt)
        .await
        .map_err(|source| GitError::Io {
            op: "frozen_diff",
            source,
        })?;
    let tracked = git_stdout_capped(
        "frozen_diff",
        wt,
        [tok("diff"), tok("--no-color"), tok("HEAD"), tok("--")],
        MAX_FROZEN_DIFF_BYTES,
    )
    .await?;

    // One directory fd for the worktree root, opened O_NOFOLLOW: every untracked file is read
    // relative to it with `openat`, never by re-walking a path string.
    let root_dir = open_root_dir(&root).map_err(|source| GitError::Io {
        op: "frozen_diff",
        source,
    })?;

    // Once per freeze, not once per file: whether git honours the executable bit here at all.
    let exec_bit = honours_file_mode(wt).await;

    let (tracked, tracked_truncated) = tracked.into_stdout();
    let mut text = CappedDiff::from_prefix(tracked.into_bytes(), tracked_truncated);
    let mut symlinks = Vec::new();
    for file in changed.iter().filter(|c| c.is_untracked()) {
        let (section, inlined) =
            untracked_section(wt, &root, root_dir.as_fd(), &file.path, exec_bit).await;
        text.push(section.as_bytes());
        if !inlined {
            symlinks.push(file.path.clone());
        }
    }

    finish_diff(
        out,
        text,
        changed.into_iter().map(|c| c.path).collect(),
        symlinks,
    )
    .await
}

/// The same diff as [`frozen_diff`], derived from the **index** against `pre_sha`.
///
/// This is what an approval hashes, and it exists so that the object that was verified is the object
/// that gets committed (Codex review of T35, round 2, finding 1). Verifying the *worktree* and then
/// committing the *index* leaves a window — anything written between the two lands in the commit
/// under a hash nobody checked. Staging first and hashing the staged content closes it: `git commit`
/// without `-a` commits exactly the index this measured.
///
/// The text must be byte-comparable with what the reviewer was shown, so it is assembled by the same
/// rules in the same order:
///
/// * `--no-renames`, because the freeze saw an unstaged rename as a delete plus an untracked add and
///   `git diff --cached` would otherwise collapse the pair into one rename section;
/// * the tracked half is `git diff --cached <pre_sha> --` restricted to the paths that already
///   existed at `pre_sha`, which is what `git diff HEAD` covered at freeze time (untracked files are
///   absent from it);
/// * every path that is new at `pre_sha` is then appended through [`render_new_file`], fed from the
///   index instead of the worktree — same renderer, same order (both sources are path-sorted), and
///   the same refusal to read through a symlink: a staged symlink is described by its target, never
///   followed.
///
/// # Errors
/// [`GitError::Failed`] / [`GitError::Timeout`] from git, [`GitError::Io`] if `out` cannot be
/// written, [`GitError::InvalidRef`] for a `pre_sha` that is not a validated sha.
pub async fn frozen_diff_cached(
    wt: &Path,
    pre_sha: &str,
    out: &Path,
) -> Result<DiffStat, GitError> {
    checked_sha("frozen_diff_cached", pre_sha)?;
    let staged = staged_changes(wt, pre_sha).await?;
    let (new, existing): (Vec<&ChangedFile>, Vec<&ChangedFile>) =
        staged.iter().partition(|file| file.is_untracked());

    let mut text = if existing.is_empty() {
        CappedDiff::new()
    } else {
        let mut args: Vec<OsString> = vec![
            "diff".into(),
            "--no-color".into(),
            "--no-renames".into(),
            "--cached".into(),
            "--end-of-options".into(),
            pre_sha.into(),
            "--".into(),
        ];
        args.extend(existing.iter().map(|file| OsString::from(&file.path)));
        let tracked =
            git_stdout_capped("frozen_diff_cached", wt, &args, MAX_FROZEN_DIFF_BYTES).await?;
        let (tracked, tracked_truncated) = tracked.into_stdout();
        CappedDiff::from_prefix(tracked.into_bytes(), tracked_truncated)
    };

    let mut symlinks = Vec::new();
    for file in &new {
        let (section, inlined) = index_section(wt, &file.path).await?;
        text.push(section.as_bytes());
        if !inlined {
            symlinks.push(file.path.clone());
        }
    }

    // The **order** matters as much as the membership: `changed_files` reports the tracked changes
    // first and the untracked ones after, each group path-sorted, and `diff.frozen{files}` is that
    // list. An approval compares its own list with the reviewed one, so this has to be assembled
    // the same way round rather than globally sorted.
    let files = existing
        .iter()
        .chain(new.iter())
        .map(|file| file.path.clone())
        .collect();
    finish_diff(out, text, files, symlinks).await
}

/// Every path staged against `pre_sha`, path-sorted, with `??` standing for "new at `pre_sha`" so
/// the entry classifies exactly as the freeze's untracked entries did.
async fn staged_changes(wt: &Path, pre_sha: &str) -> Result<Vec<ChangedFile>, GitError> {
    let out = git(
        "staged_changes",
        wt,
        [
            tok("diff"),
            tok("--cached"),
            tok("--no-renames"),
            tok("--name-status"),
            tok("-z"),
            tok("--end-of-options"),
            OsStr::new(pre_sha),
        ],
    )
    .await?;

    // `-z` output is `<status>\0<path>\0…`; `--no-renames` guarantees one path per entry.
    let stdout = out.stdout();
    let mut fields = stdout.split('\0').filter(|f| !f.is_empty());
    let mut files = Vec::new();
    while let (Some(status), Some(path)) = (fields.next(), fields.next()) {
        files.push(ChangedFile {
            path: path.to_string(),
            status: if status.starts_with('A') {
                "??".to_string()
            } else {
                status.to_string()
            },
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// One new-file section rendered from the **index**: the blob git would commit, never the file on
/// disk.
///
/// A staged symlink (mode 120000) is described by its target exactly as the freeze describes one,
/// and is never followed — the blob *is* the target string, so there is nothing to follow. A gitlink
/// or anything else that is not a regular blob is refused rather than guessed at.
async fn index_section(wt: &Path, rel: &str) -> Result<(String, bool), GitError> {
    let listed = git(
        "index_section",
        wt,
        [
            tok("ls-files"),
            tok("--stage"),
            tok("-z"),
            tok("--"),
            OsStr::new(rel),
        ],
    )
    .await?;
    // `<mode> <sha> <stage>\t<path>\0`
    let stdout = listed.stdout();
    let Some(entry) = stdout.split('\0').find(|e| !e.is_empty()) else {
        return Ok(render_new_file(
            rel,
            NewContent::Rejected {
                reason: "not in the index".to_string(),
            },
        ));
    };
    let mut parts = entry.split_whitespace();
    let (Some(mode), Some(blob)) = (parts.next(), parts.next()) else {
        return Ok(render_new_file(
            rel,
            NewContent::Rejected {
                reason: "unreadable index entry".to_string(),
            },
        ));
    };
    checked_sha("index_section", blob)?;

    if mode == "160000" {
        return Ok(render_new_file(
            rel,
            NewContent::Rejected {
                reason: "not a regular file".to_string(),
            },
        ));
    }

    let (bytes, truncated) = blob_capped(wt, blob, MAX_UNTRACKED_DIFF_BYTES).await?;

    if mode == "120000" {
        let target = sanitize_diff_token(&String::from_utf8_lossy(&bytes));
        return Ok(render_new_file(
            rel,
            NewContent::Symlink {
                at: sanitize_diff_token(rel),
                target,
            },
        ));
    }

    // The mode git actually recorded when the path was staged — including whether it kept the
    // executable bit, which is `core.fileMode`'s decision and not this module's to second-guess.
    let mode = if mode == MODE_EXEC {
        MODE_EXEC
    } else {
        MODE_FILE
    };
    Ok(render_new_file(
        rel,
        NewContent::Regular {
            bytes,
            truncated,
            mode,
        },
    ))
}

/// At most `max` bytes of the blob `sha`, capped by [`cap_bytes`] — **never the whole object**.
///
/// A blob's size is a worker's choice: it is whatever the worker wrote and `git add` stored, so
/// reading one into a `Vec` and truncating afterwards let a single 3 GB file cost the privileged
/// daemon 3 GB of resident memory (round-4 review, finding 3). `cat-file -s` answers the size for
/// the price of a few bytes of stdout, so the over-cap case is *known* before anything is read:
/// only then is a second child spawned, and it is cut off at `max + 1` bytes rather than drained.
///
/// The `max + 1` matters — it is what [`read_capped`] reads for the same reason, and handing both
/// sides the same one-past-the-cap prefix is what makes the capped sections byte-identical.
///
/// A prefix read that comes up short (git died mid-stream) yields a section that is *not* marked
/// truncated and so cannot hash to the reviewed diff: the approval refuses, which is the fail-closed
/// answer to "the index could not be read back".
async fn blob_capped(wt: &Path, sha: &str, max: usize) -> Result<(Vec<u8>, bool), GitError> {
    let size = blob_size(wt, sha).await?;
    if size <= max as u64 {
        let raw = git(
            "index_section",
            wt,
            [tok("cat-file"), tok("blob"), OsStr::new(sha)],
        )
        .await?
        .into_raw();
        return Ok(cap_bytes(raw, max));
    }
    let prefix = git_prefix(
        "index_section",
        wt,
        [tok("cat-file"), tok("blob"), OsStr::new(sha)],
        max + 1,
    )
    .await?;
    Ok(cap_bytes(prefix, max))
}

/// How many bytes git stores for the blob `sha`.
async fn blob_size(wt: &Path, sha: &str) -> Result<u64, GitError> {
    let out = git(
        "index_section",
        wt,
        [tok("cat-file"), tok("-s"), OsStr::new(sha)],
    )
    .await?;
    let stdout = out.stdout();
    let answer = stdout.trim();
    answer.parse::<u64>().map_err(|_| GitError::Failed {
        op: "index_section",
        status: "unreadable".to_string(),
        message: format!("git cat-file -s answered {answer:?} rather than a size"),
    })
}

/// Writes a frozen diff, creating its directory, and hashes exactly the bytes successfully written.
async fn write_diff(out: &Path, bytes: &[u8]) -> Result<String, GitError> {
    if let Some(parent) = out.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| GitError::Io {
                op: "frozen_diff",
                source,
            })?;
    }
    let mut file = tokio::fs::File::create(out)
        .await
        .map_err(|source| GitError::Io {
            op: "frozen_diff",
            source,
        })?;
    let mut hasher = Sha256::new();
    for chunk in bytes.chunks(64 * 1024) {
        file.write_all(chunk).await.map_err(|source| GitError::Io {
            op: "frozen_diff",
            source,
        })?;
        hasher.update(chunk);
    }
    file.flush().await.map_err(|source| GitError::Io {
        op: "frozen_diff",
        source,
    })?;
    Ok(hex_digest(&hasher.finalize()))
}

/// Which of `paths` a worker was never allowed to touch. Pure — no git, no I/O.
pub fn match_denylist(paths: &[String], globs: &GlobSet) -> Vec<DenylistHit> {
    if globs.is_empty() {
        return Vec::new();
    }
    paths
        .iter()
        .filter_map(|path| {
            let glob_indices = globs.matches(path);
            (!glob_indices.is_empty()).then(|| DenylistHit {
                path: path.clone(),
                glob_indices,
            })
        })
        .collect()
}

/// Move HEAD **and the index** back to `sha`, leaving every file on disk untouched.
///
/// One primitive, two remediations, both in `core::supervisor`'s finalize: a worker that committed
/// (HEAD moved) and a worker that only ran `git add` (the index moved). Either way the rule is the
/// same — the work survives, the git state a run depends on is restored — and either way the answer
/// is `reset --mixed` to the attempt's `preSha`.
///
/// `--mixed`, not `--soft`, and the difference is load-bearing. `--soft` moves HEAD alone and leaves
/// the worker's tree **staged**; the worktree then permanently fails the clean-index precondition an
/// approval insists on, so every run in which a worker committed could be reviewed and never
/// integrated (round-3 review, finding 1). `--mixed` restores exactly the state a worker that had
/// touched neither would have left behind — modifications unstaged, new files untracked — which is
/// the state both freezes and the approval path are written against.
///
/// # Errors
/// [`GitError::InvalidRef`] for a `sha` that is not 40 hex characters, plus whatever `git reset`
/// returned.
pub async fn reset_mixed(wt: &Path, sha: &str) -> Result<(), GitError> {
    checked_sha("reset_mixed", sha)?;
    git(
        "reset_mixed",
        wt,
        [
            tok("reset"),
            tok("--mixed"),
            tok("--quiet"),
            tok("--end-of-options"),
            OsStr::new(sha),
        ],
    )
    .await?;
    Ok(())
}

/// Whether the index in `wt` still matches HEAD — `false` means something is staged.
///
/// `git diff --cached --quiet` exits **1** when the index differs from HEAD, which is exactly the
/// question. **Only exit 1 is an answer.** Every other failure — 128 for a corrupt index or an
/// unreadable object, a signal, a `git` that could not start — is a fault, and folding it into
/// "dirty" sent the human to `git reset` for a problem no reset would fix (round-4 review, finding
/// 5). Both outcomes stop an approval; only one of them is true.
///
/// # Errors
/// Whatever git returned, for any failure that is not the exit-1 "there are differences".
pub async fn index_is_clean(wt: &Path) -> Result<bool, GitError> {
    let output = git_raw(
        "verify_index",
        wt,
        [tok("diff"), tok("--cached"), tok("--quiet")],
    )
    .await?;
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    Err(failed("verify_index", &output))
}

/// Refuses when anything is already staged in `wt`.
///
/// The precondition of the whole approval path: an approval stages the reviewed paths and commits
/// the index, so an index that already held something would commit bytes nobody reviewed.
///
/// # Errors
/// [`GitError::Failed`] with `op: "verify_index"` when the index is dirty, or whatever
/// [`index_is_clean`] returned.
pub async fn assert_index_clean(wt: &Path) -> Result<(), GitError> {
    if index_is_clean(wt).await? {
        return Ok(());
    }
    Err(GitError::Failed {
        op: "verify_index",
        status: "refused".to_string(),
        message: "the index already holds staged changes; nothing was committed".to_string(),
    })
}

/// Stages exactly `files` — no more, and never the worktree at large.
///
/// **The path set is the contract, not a convenience.** It used to be `git add -A -- .`, which
/// stages whatever is in the worktree at commit time — so a file changed after a reviewer passed the
/// frozen diff rode into the integration under that PASS. The caller passes the reviewed set
/// (`diff.frozen{files}`, carried on the gate's `CommitTarget`) and nothing else is staged.
/// `git add` stages a deletion as readily as a modification, so a reviewed removal still commits.
///
/// Every path is checked before it reaches an argv: non-empty, relative, no `..` component, no NUL,
/// no newline, no leading `-` and no leading `:`. The paths come from `git status --porcelain -z` on
/// a worktree a model has been writing in, so they are untrusted input like any other; `--` then
/// separates them from the flags (S4) and `GIT_LITERAL_PATHSPECS` (set for every call in this
/// module) stops any of them being read as a pattern. They are staged in batches so a large change
/// set cannot approach `ARG_MAX`.
///
/// # Errors
/// [`GitError::InvalidRef`] for an empty path set or a path that fails the checks above, plus
/// whatever `git add` returns.
pub async fn stage_paths(wt: &Path, files: &[String]) -> Result<(), GitError> {
    if files.is_empty() {
        return Err(GitError::InvalidRef {
            op: "stage_paths",
            value: "<no files>".to_string(),
        });
    }
    for file in files {
        check_repo_relative("stage_paths", file)?;
    }
    for chunk in files.chunks(STAGE_BATCH) {
        let mut args: Vec<OsString> = vec!["add".into(), "--".into()];
        args.extend(chunk.iter().map(OsString::from));
        git("stage_paths", wt, &args).await?;
    }
    Ok(())
}

/// Unstages exactly `files`, restoring the clean index [`assert_index_clean`] insisted on.
///
/// Cleanup for a refused or interrupted approval: the worktree is a human's, and leaving a half
/// staged index behind after deciding not to commit would be a side effect of doing nothing.
///
/// **Path-scoped, never a blanket `git reset`.** The approval only ever stages the reviewed paths,
/// so those are the only ones it may put back; a bare reset would also throw away work a human had
/// staged in that worktree themselves.
///
/// # Errors
/// [`GitError::InvalidRef`] for a path that fails [`check_repo_relative`], plus whatever `git reset`
/// returned.
pub async fn unstage_paths(wt: &Path, files: &[String]) -> Result<(), GitError> {
    if files.is_empty() {
        return Ok(());
    }
    for file in files {
        check_repo_relative("unstage_paths", file)?;
    }
    for chunk in files.chunks(STAGE_BATCH) {
        let mut args: Vec<OsString> = vec!["reset".into(), "--quiet".into(), "--".into()];
        args.extend(chunk.iter().map(OsString::from));
        git("unstage_paths", wt, &args).await?;
    }
    Ok(())
}

/// Commits **the index** — never the worktree — and returns the new HEAD sha.
///
/// No `-a` and no staging of its own: whatever [`stage_paths`] put in the index, and whatever the
/// caller then verified, is exactly what this writes.
///
/// **S7**: the message is built here from `msg` — subject sanitized to one line and truncated to
/// [`MAX_SUBJECT_BYTES`] on a char boundary, body stripped of any forged `Acp-<word>-Id:` line —
/// and the only trailers on the commit are the `(key, value)` pairs the control plane passed in.
/// Verified on git 2.54: several `--trailer` flags may be given to one `git commit`, so no
/// `--amend` chaining is needed.
///
/// **No hooks run, and the commit is read back to prove it.** The repository's hooks are the one
/// thing that runs *after* everything above has been verified: a `pre-commit` hook may `git add`
/// anything it likes into the index that was just hashed, a `commit-msg` or `prepare-commit-msg`
/// hook may rewrite the message and drop the `Acp-Gate-Id` trailer the control plane reconciles on,
/// and a `post-commit` hook may `git commit --amend` the finished commit into a different one
/// (round-4 review, finding 2). The content is already reviewed and hashed, so running the owner's
/// hooks buys nothing and re-opens exactly the window the check-stage-hash order closes.
///
/// Two mechanisms, because `--no-verify` alone is not enough — verified on git 2.54, it suppresses
/// `pre-commit` and `commit-msg` and **not** `prepare-commit-msg` or `post-commit`:
///
/// * `-c core.hooksPath=`[`NO_HOOKS_PATH`], before the subcommand where a `-c` has to go, so git
///   looks for every hook in a place no hook can exist;
/// * `--no-verify` as well, which costs nothing and does not depend on that config being honoured.
///
/// Then [`verify_commit`] reads the object back: its parent is `pre_sha`, it touches exactly
/// `files`, and it still carries every trailer. Anything else refuses with `op: "verify_commit"`
/// rather than reporting a sha the caller would record as the reviewed change.
///
/// Hooks still run for every commit a human or a worker makes themselves; this is only the control
/// plane's own integrate commit.
///
/// # Errors
/// [`GitError::InvalidRef`] for a `pre_sha` that is not a validated sha, [`GitError::Failed`] with
/// `op: "verify_commit"` when the finished commit is not the one that was staged, plus whatever
/// `git commit` or `git rev-parse` returned.
pub async fn commit_staged(
    wt: &Path,
    msg: &CommitMessage,
    trailers: &[(&str, &str)],
    pre_sha: &str,
    files: &[String],
) -> Result<String, GitError> {
    checked_sha("commit_staged", pre_sha)?;
    let mut args: Vec<OsString> = vec![
        "-c".into(),
        format!("core.hooksPath={NO_HOOKS_PATH}").into(),
        "commit".into(),
        "--no-verify".into(),
        "-m".into(),
        build_commit_message(msg).into(),
    ];
    for (key, value) in trailers {
        args.push("--trailer".into());
        args.push(format!("{key}={value}").into());
    }
    git("commit_staged", wt, &args).await?;

    let sha = head_sha(wt).await?;
    verify_commit(wt, &sha, pre_sha, files, trailers).await?;
    Ok(sha)
}

/// Reads the finished commit back and refuses anything that is not the commit that was staged.
///
/// The commit is the last thing this module does and the first thing anybody trusts, so it is
/// checked from the repository rather than assumed from the exit status. Three questions, each one
/// a way the object could differ from what was verified:
///
/// * **parent** — `%P` must be exactly `pre_sha`. An amend rewrites the commit in place, so HEAD
///   afterwards is a *different* object; its parent is the only field that says which commit it was
///   built on, and a caller that recorded the amended sha would be recording an unreviewed change.
/// * **files** — `diff-tree` against the parent must name the reviewed set. Compared as sets:
///   `changed_files` orders tracked before untracked and git orders by tree, and the disagreement
///   that matters is membership.
/// * **trailers** — every `(key, value)` must still be a line of the message, or the gate cannot
///   find its own commit again and reconciliation retries a commit that already happened.
async fn verify_commit(
    wt: &Path,
    sha: &str,
    pre_sha: &str,
    files: &[String],
    trailers: &[(&str, &str)],
) -> Result<(), GitError> {
    let refused = |message: String| GitError::Failed {
        op: "verify_commit",
        status: "refused".to_string(),
        message,
    };

    let parents = git(
        "verify_commit",
        wt,
        [
            tok("show"),
            tok("-s"),
            tok("--format=%P"),
            tok("--end-of-options"),
            OsStr::new(sha),
        ],
    )
    .await?;
    let parents_stdout = parents.stdout();
    let parents = parents_stdout.trim();
    if parents != pre_sha {
        return Err(refused(format!(
            "the commit that was written is not the one that was staged: {sha} has parent(s) \
             {parents:?}, expected {pre_sha}"
        )));
    }

    let listed = git(
        "verify_commit",
        wt,
        [
            tok("diff-tree"),
            tok("--no-commit-id"),
            tok("--name-only"),
            tok("--no-renames"),
            tok("-r"),
            tok("-z"),
            tok("--end-of-options"),
            OsStr::new(sha),
        ],
    )
    .await?;
    let listed_stdout = listed.stdout();
    let mut committed: Vec<&str> = listed_stdout
        .split('\0')
        .filter(|p| !p.is_empty())
        .collect();
    committed.sort_unstable();
    let mut reviewed: Vec<&str> = files.iter().map(String::as_str).collect();
    reviewed.sort_unstable();
    if committed != reviewed {
        return Err(refused(format!(
            "the commit does not hold the reviewed change set: expected {reviewed:?} got \
             {committed:?}"
        )));
    }

    let body = git(
        "verify_commit",
        wt,
        [
            tok("show"),
            tok("-s"),
            tok("--format=%B"),
            tok("--end-of-options"),
            OsStr::new(sha),
        ],
    )
    .await?;
    for (key, value) in trailers {
        let expected = format!("{key}: {value}");
        if !body
            .stdout()
            .lines()
            .any(|line| line.trim_end() == expected)
        {
            return Err(refused(format!(
                "the commit message no longer carries {expected:?}, so the gate could not find \
                 this commit again"
            )));
        }
    }
    Ok(())
}

/// [`stage_paths`] then [`commit_staged`], for a caller with nothing to verify in between.
///
/// The gate path deliberately does **not** use this: it interleaves the index check and the
/// staged-content hash between the two halves, which is what binds the commit to the reviewed diff.
///
/// # Errors
/// Whatever either half returns.
pub async fn commit_all(
    wt: &Path,
    msg: &CommitMessage,
    files: &[String],
    trailers: &[(&str, &str)],
) -> Result<String, GitError> {
    // Read before staging: this is the commit the new one has to sit on, and [`commit_staged`]
    // checks that it did.
    let pre_sha = head_sha(wt).await?;
    stage_paths(wt, files).await?;
    commit_staged(wt, msg, trailers, &pre_sha, files).await
}

/// Rejects a path that is not a plain repo-relative one: absolute, escaping, empty, or carrying a
/// byte no path in a git worktree legitimately has.
///
/// `..` is refused outright rather than normalized — the caller's set comes from `git status`, which
/// never emits one, so its presence means the set was tampered with and the fail-closed answer is
/// to stage nothing.
fn check_repo_relative(op: &'static str, path: &str) -> Result<(), GitError> {
    let bad = path.is_empty()
        || Path::new(path).is_absolute()
        || path.contains('\0')
        || path.contains('\n')
        // `:` opens git's pathspec magic (`:(glob)`, `:(top)`, `:/`). `GIT_LITERAL_PATHSPECS` is
        // what actually disables it for every call this module makes; refusing the prefix as well
        // is the belt to that braces, so a path that *looks* like magic never reaches an argv even
        // if some future call is made without the environment.
        || path.starts_with(':')
        || path.starts_with('-')
        || Path::new(path)
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)));
    if bad {
        return Err(GitError::InvalidRef {
            op,
            value: path.to_string(),
        });
    }
    Ok(())
}

/// sha256 of a file, lowercase hex — the value `diff.frozen{diffHash}` carries, the one a reviewer
/// must echo (Rev 25), and the one an approval re-computes before it commits.
///
/// Hashing the **file** rather than an in-memory stat is deliberate: the file is what the reviewer
/// was pointed at, so the hash covers exactly the bytes it could read. `None` when the file cannot
/// be read — hashing `""` would produce a perfectly well-formed digest of the wrong bytes, and
/// every caller has to fail closed instead.
pub async fn sha256_file(path: &Path) -> Option<String> {
    let mut file = tokio::fs::File::open(path).await.ok()?;
    let mut hasher = Sha256::new();
    // Heap-backed: this async function is nested inside already-large supervisor/gate futures, and
    // embedding a 64 KiB array in each future needlessly spends the test/runtime thread's stack.
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await.ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hex_digest(&hasher.finalize()))
}

fn hex_digest(digest: &[u8]) -> String {
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The most recent commit carrying `<key>: <value>` as a trailer line, if any.
///
/// Used to reconcile a gate left `resolving` by a crash: `value` is always a validated UUID and the
/// pattern is a single attached `--grep=` token, so nothing here is injectable.
pub async fn find_commit_by_trailer(
    wt: &Path,
    key: &str,
    value: &str,
) -> Result<Option<String>, GitError> {
    let pattern = format!("--grep=^{key}: {value}$");
    let out = git(
        "find_commit_by_trailer",
        wt,
        [
            tok("log"),
            tok("--all"),
            tok("--format=%H"),
            OsStr::new(&pattern),
        ],
    )
    .await?;

    let stdout = out.stdout();
    match stdout.lines().map(str::trim).find(|l| !l.is_empty()) {
        None => Ok(None),
        Some(sha) => checked_sha("find_commit_by_trailer", sha).map(Some),
    }
}

// ---------------------------------------------------------------------------
// Message construction (S7)
// ---------------------------------------------------------------------------

/// Does this line look like one of the control plane's own identity trailers?
///
/// Hand-written rather than a regex (the design bans `regex` as a direct dependency): the line is
/// stripped of leading whitespace, must start with `Acp-` (case-insensitively), and the token up to
/// the `:` must be `<word>-Id` where `<word>` is a non-empty run of ASCII alphanumerics and dashes.
/// Whitespace before the `:` is tolerated, because git's trailer parser tolerates it too.
pub fn is_acp_trailer_line(line: &str) -> bool {
    let line = line.trim_start();
    let Some(prefix) = line.get(..4) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case("acp-") {
        return false;
    }
    let Some(colon) = line.find(':') else {
        return false;
    };
    let token = line[..colon].trim_end();
    if !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return false;
    }
    // The token is all ASCII by now, so byte slicing is safe: it must end in "-Id" and have a
    // non-empty <word> between the "Acp-" prefix and that suffix.
    let Some(cut) = token.len().checked_sub(3) else {
        return false;
    };
    let (head, suffix) = token.split_at(cut);
    suffix.eq_ignore_ascii_case("-id") && head.len() > 4 // "Acp-" plus a non-empty <word>
}

/// Build the full commit message: sanitized subject, blank line, sanitized body.
fn build_commit_message(msg: &CommitMessage) -> String {
    let subject = subject_line(&msg.title);
    let body = strip_forged_trailers(&msg.body);
    if body.is_empty() {
        subject
    } else {
        format!("{subject}\n\n{body}\n")
    }
}

/// First line of `title`, control characters neutralized, truncated to [`MAX_SUBJECT_BYTES`].
fn subject_line(title: &str) -> String {
    let first = title.split(['\n', '\r']).next().unwrap_or_default();
    let cleaned: String = first
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let subject = truncate_on_char_boundary(cleaned.trim(), MAX_SUBJECT_BYTES).trim_end();
    if subject.is_empty() {
        FALLBACK_SUBJECT.to_string()
    } else {
        subject.to_string()
    }
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a UTF-8 char boundary.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = 0;
    for (i, c) in s.char_indices() {
        let next = i + c.len_utf8();
        if next > max {
            break;
        }
        end = next;
    }
    &s[..end]
}

/// Drop every line of `body` that looks like an `Acp-*-Id:` trailer (S7).
fn strip_forged_trailers(body: &str) -> String {
    let kept: Vec<&str> = body.lines().filter(|l| !is_acp_trailer_line(l)).collect();
    kept.join("\n").trim_end().to_string()
}

// ---------------------------------------------------------------------------
// Diff helpers
// ---------------------------------------------------------------------------

/// The single budget applied to the complete document produced by either freeze.
///
/// It retains one byte beyond the limit so exact-limit output can be distinguished from truncated
/// output. Once overflow is known, later sections are ignored but callers still inspect every path
/// to produce the complete `files` and `symlinks` metadata.
struct CappedDiff {
    bytes: Vec<u8>,
    overflowed: bool,
}

impl CappedDiff {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            overflowed: false,
        }
    }

    /// Seeds the document from a tracked diff without copying its allocation.
    fn from_prefix(mut bytes: Vec<u8>, overflowed: bool) -> Self {
        let retained = MAX_FROZEN_DIFF_BYTES.saturating_add(1);
        let too_long = bytes.len() > retained;
        bytes.truncate(retained);
        Self {
            bytes,
            overflowed: overflowed || too_long,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let retained = MAX_FROZEN_DIFF_BYTES.saturating_add(1);
        let room = retained.saturating_sub(self.bytes.len());
        let keep = room.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..keep]);
        if keep < bytes.len() {
            self.overflowed = true;
        }
    }

    fn finish(self) -> Vec<u8> {
        let (mut bytes, capped) = cap_bytes(self.bytes, MAX_FROZEN_DIFF_BYTES);
        if self.overflowed || capped {
            bytes.extend_from_slice(FROZEN_DIFF_TRUNCATION_MARKER);
        }
        bytes
    }
}

/// Finalizes both freeze variants through one byte-budget, counter, writer and hasher path.
async fn finish_diff(
    out: &Path,
    text: CappedDiff,
    files: Vec<String>,
    symlinks: Vec<String>,
) -> Result<DiffStat, GitError> {
    let bytes = text.finish();
    let (added, deleted) = count_diff_lines(&bytes);
    let diff_hash = write_diff(out, &bytes).await?;
    Ok(DiffStat {
        files,
        added,
        deleted,
        diff_hash,
        symlinks,
    })
}

/// How an untracked path may be represented in the frozen diff.
enum Untracked {
    /// The path itself, or a directory component of it, is a symlink. `at` is the component that is
    /// the link, `target` its (sanitized) target — the daemon never reads through it.
    Symlink { at: String, target: String },
    /// Not a regular file, not inspectable, or it resolves outside the worktree.
    Rejected { reason: &'static str },
    /// A real regular file inside the worktree: safe to inline.
    Regular,
}

/// Decide whether an untracked path may be read, walking it component by component with
/// `symlink_metadata` so a symlinked *directory* is caught as well as a symlinked leaf.
///
/// `root` is the already-canonicalized worktree, so the symlinks macOS puts above a `TempDir`
/// (`/var` → `/private/var`) are irrelevant — only links a worker could create below it matter.
async fn classify_untracked(wt: &Path, root: &Path, rel: &str) -> Untracked {
    let mut prefix = PathBuf::new();
    let mut leaf = None;
    for component in Path::new(rel).components() {
        let Component::Normal(name) = component else {
            // git never emits `..`, `.` or an absolute path in porcelain output; refuse anyway.
            return Untracked::Rejected {
                reason: "path is not a plain relative path",
            };
        };
        prefix.push(name);
        let full = wt.join(&prefix);
        let Ok(meta) = tokio::fs::symlink_metadata(&full).await else {
            return Untracked::Rejected {
                reason: "could not be inspected",
            };
        };
        if meta.file_type().is_symlink() {
            let target = match tokio::fs::read_link(&full).await {
                Ok(target) => sanitize_diff_token(&target.to_string_lossy()),
                Err(_) => "(unreadable link target)".to_string(),
            };
            return Untracked::Symlink {
                at: sanitize_diff_token(&prefix.to_string_lossy()),
                target,
            };
        }
        leaf = Some(meta);
    }

    let Some(meta) = leaf else {
        return Untracked::Rejected {
            reason: "empty path",
        };
    };
    if !meta.is_file() {
        return Untracked::Rejected {
            reason: "not a regular file",
        };
    }
    match tokio::fs::canonicalize(wt.join(rel)).await {
        Ok(resolved) if resolved.starts_with(root) => Untracked::Regular,
        Ok(_) => Untracked::Rejected {
            reason: "resolves outside the worktree",
        },
        Err(_) => Untracked::Rejected {
            reason: "could not be resolved",
        },
    }
}

/// A synthetic unified-diff section for one path that does not exist in the base commit.
///
/// Returns the section and whether the file's contents were inlined; `false` means the path is
/// reported by name (and, for a symlink, by target) only — see [`frozen_diff`].
///
/// `classify_untracked` decides only *how to describe* the path. The contents, if any, come from
/// [`open_under_root`] — the single read route, which re-derives safety from file descriptors
/// rather than trusting the classification.
async fn untracked_section(
    wt: &Path,
    root: &Path,
    root_fd: BorrowedFd<'_>,
    rel: &str,
    exec_bit: bool,
) -> (String, bool) {
    match classify_untracked(wt, root, rel).await {
        Untracked::Symlink { at, target } => {
            render_new_file(rel, NewContent::Symlink { at, target })
        }
        Untracked::Rejected { reason } => render_new_file(
            rel,
            NewContent::Rejected {
                reason: reason.to_string(),
            },
        ),
        Untracked::Regular => {
            // The read route. If anything changed under us since classification — a parent replaced
            // by a symlink, the leaf replaced by one, the file replaced by a fifo — this fails
            // (ELOOP/ENOTDIR/…) and no contents are produced.
            let Ok(file) = open_under_root(root_fd, rel) else {
                return render_new_file(
                    rel,
                    NewContent::Rejected {
                        reason: "could not be opened without following a symlink".to_string(),
                    },
                );
            };
            // Off the descriptor that was just validated, never a second look at the path.
            let mode = regular_mode(&file, exec_bit);
            let Ok((bytes, truncated)) = read_capped(file, MAX_UNTRACKED_DIFF_BYTES).await else {
                return render_new_file(rel, NewContent::Unreadable);
            };
            // What git would *store* for this path, not what is on disk. The two differ whenever an
            // attribute or a filter driver applies — `* text=auto` rewrites CRLF, a `filter.*.clean`
            // rewrites whatever it likes — and the reviewer has to be shown the bytes that would
            // actually be committed, or an approval that re-derives them from the index disagrees
            // with a review that was honest about the worktree (round-3 review, finding 2).
            let bytes = cleaned_bytes(wt, rel, bytes).await;
            render_new_file(
                rel,
                NewContent::Regular {
                    bytes,
                    truncated,
                    mode,
                },
            )
        }
    }
}

/// `bytes` as git would store them for `rel`: the clean filter and the eol attributes applied.
///
/// The round trip is `hash-object -w --stdin --path=<rel>` followed by `cat-file blob`, and both
/// halves are deliberate:
///
/// * **`--stdin`, never a path.** The bytes were read through the `openat`/`O_NOFOLLOW` route that
///   refuses to follow a symlink; handing git the path instead would have it open the file itself
///   and read straight through one (V4).
/// * **`-w`.** There is no way to ask git for filtered *content* without an object to read back, so
///   the blob is written. It is the same blob `git add` would write at approval time, so nothing new
///   is put in the repository that integrating would not have put there anyway; on a run that is
///   never integrated it is a dangling object, which `git gc` prunes.
///
/// Any failure leaves the raw bytes: a repository whose filter driver is broken should be reviewed
/// as it stands rather than not at all, and the approval's own hash check is what refuses to
/// integrate on a disagreement.
///
/// **Known limit — a large file *and* a normalizing attribute.** A file past
/// [`MAX_UNTRACKED_DIFF_BYTES`] is capped *before* this runs, so the review normalizes a prefix while
/// the approval normalizes the whole blob and caps that. With no attribute in play the two are the
/// same bytes by construction ([`cap_bytes`]); with one, the documents differ for a file nobody
/// touched. The approval then refuses, and `gates::name_the_disagreement` re-freezes the worktree to
/// say so in those words rather than blaming the worker. Reviewing 256 KiB of one file is already
/// the cap's own answer to "how much of a diff is worth showing".
async fn cleaned_bytes(wt: &Path, rel: &str, bytes: Vec<u8>) -> Vec<u8> {
    let hashed = git_stdin(
        "cleaned_bytes",
        wt,
        [
            OsString::from("hash-object"),
            OsString::from("-w"),
            OsString::from("--stdin"),
            // Attached, so a path that starts with `-` cannot be read as a flag.
            OsString::from(format!("--path={rel}")),
        ],
        &bytes,
    )
    .await;
    let Ok(out) = hashed else {
        tracing::warn!(path = %rel, "could not ask git what it would store; the raw bytes stand");
        return bytes;
    };
    let blob = out.stdout().trim().to_string();
    if checked_sha("cleaned_bytes", &blob).is_err() {
        return bytes;
    }
    match git(
        "cleaned_bytes",
        wt,
        [tok("cat-file"), tok("blob"), OsStr::new(&blob)],
    )
    .await
    {
        Ok(stored) => stored.into_raw(),
        Err(err) => {
            tracing::warn!(path = %rel, %err, "could not read back the stored blob; the raw bytes stand");
            bytes
        }
    }
}

/// What a new file's section is rendered *from*, so the same renderer serves both sources: the
/// worktree (when the diff is frozen for review) and the index (when an approval re-derives it).
///
/// That sharing is the point. The approval's hash may only be compared with the reviewer's if both
/// texts were produced by the same rules, down to the truncation marker and the missing final
/// newline — so there is exactly one place those rules live.
enum NewContent {
    Symlink {
        at: String,
        target: String,
    },
    Rejected {
        reason: String,
    },
    /// The bytes exist but could not be read back.
    Unreadable,
    Regular {
        bytes: Vec<u8>,
        truncated: bool,
        /// [`MODE_FILE`] or [`MODE_EXEC`], derived by the caller from whichever side it read.
        mode: &'static str,
    },
}

/// Renders one new-file section. Pure: every source-specific decision is already in `content`.
fn render_new_file(rel: &str, content: NewContent) -> (String, bool) {
    // A filename, like a link target, may legally contain a newline: sanitize anything that is
    // interpolated into diff structure, or a worker could forge diff headers in the reviewer's view.
    let name = sanitize_diff_token(rel);

    match content {
        NewContent::Symlink { at, target } => {
            // Rendered the way git renders a symlink — mode 120000, content = the target string —
            // so the reviewer sees exactly what was planted, and nothing it points at.
            let mut section = format!(
                "diff --git a/{name} b/{name}\nnew file mode 120000\n--- /dev/null\n+++ b/{name}\n"
            );
            section.push_str("@@ -0,0 +1 @@\n");
            section.push_str(&format!("+{target}\n"));
            section.push_str("\\ No newline at end of file\n");
            if at != name {
                section.push_str(&format!(
                    "(not inlined: {at} is a symlink; contents were never read)\n"
                ));
            } else {
                section.push_str("(symlink: target shown, contents were never read)\n");
            }
            (section, false)
        }
        NewContent::Rejected { reason } => {
            let section = format!(
                "diff --git a/{name} b/{name}\nnew file mode 100644\n--- /dev/null\n+++ b/{name}\n\
                 (not inlined: {reason})\n"
            );
            (section, false)
        }
        NewContent::Unreadable => {
            let section = format!(
                "diff --git a/{name} b/{name}\nnew file mode 100644\n--- /dev/null\n+++ b/{name}\n\
                 (untracked file could not be read)\n"
            );
            (section, false)
        }
        NewContent::Regular {
            bytes,
            truncated,
            mode,
        } => {
            let mut section = format!(
                "diff --git a/{name} b/{name}\nnew file mode {mode}\n--- /dev/null\n+++ b/{name}\n"
            );
            if bytes.contains(&0) {
                section.push_str(&format!(
                    "Binary files /dev/null and b/{name} differ ({} bytes)\n",
                    bytes.len()
                ));
                return (section, true);
            }

            let text = String::from_utf8_lossy(&bytes);
            let ends_with_newline = text.ends_with('\n');
            let lines: Vec<&str> = if ends_with_newline {
                text.strip_suffix('\n')
                    .unwrap_or(&text)
                    .split('\n')
                    .collect()
            } else if text.is_empty() {
                Vec::new()
            } else {
                text.split('\n').collect()
            };
            if lines.is_empty() {
                return (section, true);
            }

            section.push_str(&format!("@@ -0,0 +1,{} @@\n", lines.len()));
            for line in lines {
                section.push('+');
                section.push_str(line);
                section.push('\n');
            }
            if !ends_with_newline {
                section.push_str("\\ No newline at end of file\n");
            }
            if truncated {
                section.push_str("(untracked file truncated by the control plane)\n");
            }
            (section, true)
        }
    }
}

/// The mode git would store `file` under: [`MODE_EXEC`] when it is executable **and** this
/// repository honours the bit, [`MODE_FILE`] otherwise.
///
/// The metadata comes off the already-validated descriptor (`fstat`), never from a second look at
/// the path — the same rule the read route follows, for the same reason (V4).
fn regular_mode(file: &std::fs::File, exec_bit: bool) -> &'static str {
    use std::os::unix::fs::PermissionsExt as _;

    let executable = file
        .metadata()
        .is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0);
    if exec_bit && executable {
        MODE_EXEC
    } else {
        MODE_FILE
    }
}

/// Whether `core.fileMode` is on here — that is, whether `git add` would keep a file's executable
/// bit at all.
///
/// Asked rather than assumed, because the answer has to be the *index's*: on a repository with
/// `core.fileMode=false` (a mounted volume, a repo cloned on Windows) git stores 100644 for an
/// executable file, so a freeze that read the bit straight off `st_mode` would render 100755, the
/// approval would re-derive 100644 from the index, and the two documents would differ for a file
/// nobody touched — the exact failure this round is about, in a new place.
///
/// Unset means on, which is git's own default; an unreadable answer means on, because that is the
/// case where the executable bit matters and being wrong the other way hides a real difference.
async fn honours_file_mode(wt: &Path) -> bool {
    let out = git_raw(
        "file_mode",
        wt,
        [
            tok("config"),
            tok("--bool"),
            tok("--get"),
            tok("core.fileMode"),
        ],
    )
    .await;
    match out {
        // `--get` exits 1 when the key is not set at all.
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim() != "false",
        _ => true,
    }
}

/// Make a worker-chosen string safe to interpolate into diff structure: no line breaks, no other
/// control characters, bounded length.
fn sanitize_diff_token(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    truncate_on_char_boundary(&cleaned, MAX_DIFF_TOKEN_BYTES).to_string()
}

/// Open the (already canonical) worktree root as a directory fd — the anchor every untracked read
/// is resolved against.
fn open_root_dir(root: &Path) -> std::io::Result<OwnedFd> {
    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL")
    })?;
    // SAFETY: `path` is a valid NUL-terminated C string that outlives the call; the returned fd is
    // immediately owned by an `OwnedFd`, which closes it.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, valid, unowned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open `rel` **relative to `root_fd`**, refusing to traverse a symlink at any component.
///
/// This is the only route by which the control plane reads a worker-chosen file, and it is
/// deliberately descriptor-based rather than path-based. Each component is opened with
/// `openat(parent_fd, name, O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC)` and the *resulting fd* is the
/// parent for the next component, so there is no window in which a checked directory can be
/// replaced by a symlink before it is used: a swap after the open simply does not affect the fd
/// already held, and a swap before it makes that `openat` fail (`ELOOP`, or `ENOTDIR` on
/// BSD/macOS, which report the `O_DIRECTORY | O_NOFOLLOW` refusal that way). The leaf is opened
/// `O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` (the last so a planted fifo cannot block the
/// daemon) and `fstat`ed — anything that is not a regular file is refused.
///
/// Failure modes a worker can provoke — `ELOOP`, `ENOTDIR`, `ENOENT`, `EACCES` — all surface as an
/// `Err`, which the caller renders as "not inlined". No error path yields contents.
fn open_under_root(root_fd: BorrowedFd<'_>, rel: &str) -> std::io::Result<std::fs::File> {
    fn refuse(reason: &'static str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, reason)
    }

    let mut components = Path::new(rel).components().peekable();
    // The directory the next component is opened relative to: the root, then each opened dir fd.
    let mut parent: Option<OwnedFd> = None;

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            // git never emits `.`, `..` or an absolute path in porcelain output; refuse anyway.
            return Err(refuse("path is not a plain relative path"));
        };
        let name = CString::new(name.as_bytes()).map_err(|_| refuse("path contains a NUL"))?;
        let dir_fd = parent
            .as_ref()
            .map_or_else(|| root_fd.as_raw_fd(), |fd| fd.as_raw_fd());
        let is_leaf = components.peek().is_none();
        let flags = if is_leaf {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };

        // SAFETY: `dir_fd` is a valid open directory descriptor owned by `root_fd` or `parent`,
        // and `name` is a valid NUL-terminated C string that outlives the call.
        let fd = unsafe { libc::openat(dir_fd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, valid, unowned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        if is_leaf {
            let file = std::fs::File::from(fd);
            if !file.metadata()?.is_file() {
                return Err(refuse("not a regular file"));
            }
            return Ok(file);
        }
        parent = Some(fd);
    }
    Err(refuse("empty path"))
}

/// Read at most `max` bytes of an already-opened file, capped by [`cap_bytes`]. Returns the bytes
/// and whether anything was dropped.
///
/// Takes the `File` rather than a path on purpose: the descriptor [`open_under_root`] validated is
/// the one that is read, so nothing can be substituted in between.
async fn read_capped(file: std::fs::File, max: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    // `max + 1` is what lets [`cap_bytes`] tell "exactly the cap" from "more than the cap".
    tokio::fs::File::from_std(file)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    Ok(cap_bytes(bytes, max))
}

/// Cut `bytes` down to `max`, back to the last newline, and say whether anything was dropped.
///
/// **Both sources of a new-file section go through this**, which is the whole point. The freeze
/// reads the worktree ([`read_capped`]) and the approval reads the index ([`blob_capped`]); when the
/// two capped a large file by different rules the documents differed for a file nobody had touched,
/// the approval refused for ever, and `gates::name_the_disagreement` blamed `.gitattributes` for it
/// (round-4 review, finding 1). One function, one rule: truncate at `max`, then cut back to the last
/// newline inside it so a section never ends mid-line — and `truncated` is derived from the same
/// comparison on both sides rather than from each caller's own idea of "too big".
///
/// The newline trim applies to binary content too: a binary section's marker is its byte count, so
/// the two sides have to agree on that count, not on whether the bytes were text.
fn cap_bytes(mut bytes: Vec<u8>, max: usize) -> (Vec<u8>, bool) {
    if bytes.len() <= max {
        return (bytes, false);
    }
    bytes.truncate(max);
    if let Some(last_newline) = bytes.iter().rposition(|b| *b == b'\n') {
        bytes.truncate(last_newline + 1);
    }
    (bytes, true)
}

/// Count added/deleted lines in a unified diff, ignoring the `+++`/`---` file headers.
fn count_diff_lines(diff: &[u8]) -> (u64, u64) {
    let mut added = 0;
    let mut deleted = 0;
    for line in diff.split(|byte| *byte == b'\n') {
        if line.starts_with(b"+++") || line.starts_with(b"---") {
            continue;
        }
        if line.starts_with(b"+") {
            added += 1;
        } else if line.starts_with(b"-") {
            deleted += 1;
        }
    }
    (added, deleted)
}

// ---------------------------------------------------------------------------
// Process plumbing
// ---------------------------------------------------------------------------

struct GitOut {
    raw: Vec<u8>,
}

impl GitOut {
    /// Takes ownership of a **successful** child's output — stderr belongs to [`failed`], which is
    /// the only thing that reads it.
    ///
    fn new(output: std::process::Output) -> Self {
        Self { raw: output.stdout }
    }

    /// A borrowed view for ordinary textual git output. Valid UTF-8 allocates nothing; replacement
    /// storage exists only while a caller is looking at malformed bytes.
    fn stdout(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.raw)
    }

    /// Consumes the one retained buffer when a caller needs an owned string.
    fn into_stdout(self) -> String {
        match String::from_utf8(self.raw) {
            Ok(stdout) => stdout,
            Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
        }
    }

    fn into_raw(self) -> Vec<u8> {
        self.raw
    }
}

/// Shorthand for a literal argv token.
fn tok(s: &str) -> &OsStr {
    OsStr::new(s)
}

/// Environment a git child inherits from the daemon, on top of the sanitized `PATH`. Mirrors the
/// inherited half of [`crate::providers::base_env`]; `HOME` is what makes `~/.gitconfig` — and so
/// the human's commit identity — apply to an integrate commit.
const INHERITED_GIT_ENV_KEYS: [&str; 3] = ["HOME", "TMPDIR", "LANG"];

/// Memo of `(raw PATH, resolved git, sanitized PATH)`.
///
/// Keyed by the `PATH` it was derived from rather than resolved unconditionally once: the daemon's
/// `PATH` never changes, so in production this resolves exactly once for the life of the process,
/// while a test that shims `PATH` still gets a correct answer instead of a stale one (an
/// unconditional `OnceLock` would make the outcome depend on which test ran first).
static GIT_PROGRAM: RwLock<Option<(OsString, PathBuf, OsString)>> = RwLock::new(None);

/// The absolute path of the `git` to run, and the sanitized `PATH` its children should see.
fn git_program() -> std::io::Result<(PathBuf, OsString)> {
    let raw = std::env::var_os("PATH").unwrap_or_default();

    let cached = {
        let memo = GIT_PROGRAM
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        memo.as_ref().and_then(|(key, program, path_env)| {
            (*key == raw).then(|| (program.clone(), path_env.clone()))
        })
    };
    if let Some(resolved) = cached {
        return Ok(resolved);
    }

    let dirs = absolute_path_entries(&raw);
    let program = resolve_program(&dirs, "git").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "git was not found in any absolute PATH entry",
        )
    })?;
    let path_env = std::env::join_paths(&dirs).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a PATH entry contains the path separator",
        )
    })?;

    let mut memo = GIT_PROGRAM
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *memo = Some((raw, program.clone(), path_env.clone()));
    Ok((program, path_env))
}

/// The entries of `path_env` that are safe to search: **absolute directories only**.
///
/// An empty entry means "the current directory" to `execvp`, and the current directory of a git
/// call is a worker's worktree; `.` and any other relative entry are the same hazard spelled out.
/// They are dropped rather than rejected, so an odd `PATH` degrades to the safe entries it has.
fn absolute_path_entries(path_env: &OsStr) -> Vec<PathBuf> {
    std::env::split_paths(path_env)
        .filter(|dir| dir.is_absolute())
        .collect()
}

/// First executable file named `name` in `dirs`, in order.
///
/// Deliberately duplicated from `providers::find_on_path` rather than shared: `workspace` must not
/// depend on `providers`, and the design defines no common utility module.
fn resolve_program(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    dirs.iter().find_map(|dir| {
        let candidate = dir.join(name);
        let meta = std::fs::metadata(&candidate).ok()?;
        (meta.is_file() && meta.permissions().mode() & 0o111 != 0).then_some(candidate)
    })
}

/// The `Command` every git invocation in this module starts from — argv, stdin and stdout are the
/// caller's to fill in.
///
/// **The program is an absolute path resolved by [`git_program`], never the bare name `"git"`, and
/// the child's environment is built from scratch.** `cwd` is a worker's worktree: `execvp` searching
/// an inherited `PATH` that contains an empty, `.` or otherwise relative entry would resolve `git`
/// against that directory, so a worker could drop an executable named `git` in its worktree and have
/// the privileged daemon run it. The child gets only the sanitized `PATH` plus `HOME`/`TMPDIR`/`LANG`
/// — the same inherited allowlist a worker gets ([`crate::providers::base_env`]) — so an ambient
/// `GIT_DIR`, `GIT_WORK_TREE` or `GIT_CONFIG_*` in the daemon's environment cannot redirect a git
/// call either. `HOME` is kept deliberately: integrate commits must use the human's git identity
/// from `~/.gitconfig`.
///
/// `kill_on_drop` is set here rather than per call site: dropping the future that owns the `Child` —
/// on a timeout, on a cancelled task — SIGKILLs and reaps the process instead of leaking it. Only
/// the direct child is signalled; killing a whole process group is `core::supervisor`'s
/// `signal_group`, which exists for worker CLIs, not for git.
fn git_command(op: &'static str, cwd: &Path) -> Result<Command, GitError> {
    let (program, path_env) = git_program().map_err(|source| GitError::Io { op, source })?;

    let mut command = Command::new(&program);
    command
        .current_dir(cwd)
        .env_clear()
        .env("PATH", &path_env)
        // **Every pathspec this module passes is a literal path, never a pattern.** The paths come
        // from `git status` on a worktree a model has been writing in, and git's pathspec magic is
        // not disabled by `--`: a file named `:(glob)*` or `:/etc/passwd` would otherwise be read
        // as a wildcard or as a from-the-repo-root path and stage something nobody reviewed. This
        // turns the whole syntax off for every git call the control plane makes (Codex review of
        // T35, round 2, finding 2).
        .env("GIT_LITERAL_PATHSPECS", "1")
        // A git call in a worker's worktree can run commands git *config* names — a
        // `filter.*.clean`, a `diff.*.textconv`, `core.fsmonitor`. The machine-wide
        // `/etc/gitconfig` is the one source of those the daemon has no reason to honour, so it is
        // switched off (design, § Residual risk). `~/.gitconfig` and the repository's own config
        // still apply: the first carries the human's commit identity, the second is the repository
        // they asked the control plane to work in.
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for key in INHERITED_GIT_ENV_KEYS {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    Ok(command)
}

/// Run one git invocation in `cwd`, bounded by [`git_op_timeout`], and hand back what it exited
/// with — **including a failure**.
///
/// stdin is `/dev/null` so git can never block waiting for input. Callers that want "non-zero is an
/// error" use [`git`]; this exists for the one caller that has to read the exit *code*, because for
/// `git diff --quiet` a non-zero status is the answer rather than a fault.
async fn git_raw<I, S>(
    op: &'static str,
    cwd: &Path,
    args: I,
) -> Result<std::process::Output, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = git_command(op, cwd)?;
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());

    let child = command
        .spawn()
        .map_err(|source| GitError::Io { op, source })?;

    let limit = git_op_timeout();
    match tokio::time::timeout(limit, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(source)) => Err(GitError::Io { op, source }),
        Err(_elapsed) => Err(GitError::Timeout {
            op,
            secs: limit.as_secs(),
        }),
    }
}

/// [`git_raw`], with a non-zero exit turned into [`GitError::Failed`]. The module's workhorse.
async fn git<I, S>(op: &'static str, cwd: &Path, args: I) -> Result<GitOut, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = git_raw(op, cwd, args).await?;
    if !output.status.success() {
        return Err(failed(op, &output));
    }
    Ok(GitOut::new(output))
}

/// The bounded prefix of a child's output, plus whether bytes beyond it were drained and dropped.
struct CappedGitOut {
    raw: Vec<u8>,
    truncated: bool,
}

impl CappedGitOut {
    fn stdout(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.raw)
    }

    fn into_stdout(self) -> (String, bool) {
        let truncated = self.truncated;
        let stdout = match String::from_utf8(self.raw) {
            Ok(stdout) => stdout,
            Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
        };
        (stdout, truncated)
    }

    fn into_raw(self) -> (Vec<u8>, bool) {
        (self.raw, self.truncated)
    }
}

/// Reads a stream to EOF while retaining at most `max + 1` bytes.
async fn read_capped_stream<R>(mut stream: R, max: usize) -> std::io::Result<CappedGitOut>
where
    R: AsyncRead + Unpin,
{
    let retained = max.saturating_add(1);
    let mut raw = Vec::with_capacity(retained.min(64 * 1024));
    let mut truncated = false;
    // Two of these futures run concurrently for stdout/stderr; keep their scratch space off the
    // executor thread's stack.
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let room = retained.saturating_sub(raw.len());
        let keep = room.min(read);
        raw.extend_from_slice(&buffer[..keep]);
        if keep < read {
            truncated = true;
        }
    }
    Ok(CappedGitOut { raw, truncated })
}

/// Runs a git command to completion while retaining only a bounded stdout prefix.
///
/// Unlike [`git_prefix`], this validates the child's final status. A diff driver may emit more than
/// the artifact budget and fail afterwards; accepting that prefix would turn failed git output into
/// a reviewable and potentially approvable document. Both pipes are therefore drained concurrently
/// with the wait, while only bounded prefixes are retained.
async fn git_stdout_capped<I, S>(
    op: &'static str,
    cwd: &Path,
    args: I,
    max: usize,
) -> Result<CappedGitOut, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = git_command(op, cwd)?;
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());

    git_command_capped(op, command, max).await
}

/// Execute an already configured trusted command with the same bounds and child cleanup.
async fn git_command_capped(
    op: &'static str,
    mut command: Command,
    max: usize,
) -> Result<CappedGitOut, GitError> {
    let mut child = command
        .spawn()
        .map_err(|source| GitError::Io { op, source })?;
    let stdout = child.stdout.take().ok_or_else(|| GitError::Io {
        op,
        source: std::io::Error::other("no stdout pipe"),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| GitError::Io {
        op,
        source: std::io::Error::other("no stderr pipe"),
    })?;

    let limit = git_op_timeout();
    let completed = tokio::time::timeout(limit, async {
        let (stdout, stderr, status) = tokio::join!(
            read_capped_stream(stdout, max),
            read_capped_stream(stderr, MAX_GIT_STDERR_BYTES),
            child.wait(),
        );
        let stdout = stdout.map_err(|source| GitError::Io { op, source })?;
        let stderr = stderr.map_err(|source| GitError::Io { op, source })?;
        let status = status.map_err(|source| GitError::Io { op, source })?;
        Ok::<_, GitError>((status, stdout, stderr))
    })
    .await;

    let (status, stdout, stderr) = match completed {
        Ok(result) => result?,
        Err(_elapsed) => {
            // Dropping the timed-out read futures closes both pipes before the kill. `kill().await`
            // also waits, so the direct child is reaped rather than left behind.
            let _ = child.kill().await;
            return Err(GitError::Timeout {
                op,
                secs: limit.as_secs(),
            });
        }
    };
    if !status.success() {
        let stderr_text = stderr.stdout();
        let stdout_text = stdout.stdout();
        let mut message = if stderr_text.trim().is_empty() {
            stdout_text.trim().to_string()
        } else {
            stderr_text.trim().to_string()
        };
        if stderr.truncated || (stderr_text.trim().is_empty() && stdout.truncated) {
            message.push_str("\n(output truncated by the control plane)");
        }
        return Err(GitError::Failed {
            op,
            status: status.to_string(),
            message,
        });
    }
    Ok(stdout)
}

/// The first `max` bytes of a git command's stdout, with the child stopped as soon as they are read.
///
/// The bound is the point: `cat-file` will happily stream an object of any size, and the caller has
/// already decided it will not look past `max` (see [`blob_capped`]). Reading a prefix and killing
/// the child keeps the daemon's memory a function of the cap rather than of what a worker wrote.
///
/// The child's exit status is deliberately **not** checked — it was cut off mid-stream, so a
/// non-zero status here says nothing about the object. A caller that needs to know the object is
/// readable establishes that first.
async fn git_prefix<I, S>(
    op: &'static str,
    cwd: &Path,
    args: I,
    max: usize,
) -> Result<Vec<u8>, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = git_command(op, cwd)?;
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|source| GitError::Io { op, source })?;
    let mut stdout = child.stdout.take().ok_or_else(|| GitError::Io {
        op,
        source: std::io::Error::other("no stdout pipe"),
    })?;

    let limit = git_op_timeout();
    let mut bytes = Vec::new();
    let read = tokio::time::timeout(limit, async {
        (&mut stdout).take(max as u64).read_to_end(&mut bytes).await
    })
    .await;
    // Close the pipe before the kill so a git still writing gets EPIPE rather than being suspended
    // on a full buffer, then reap it: `kill` is `start_kill` plus `wait`, so nothing is left behind.
    drop(stdout);
    let _ = child.kill().await;

    match read {
        Ok(Ok(_)) => Ok(bytes),
        Ok(Err(source)) => Err(GitError::Io { op, source }),
        Err(_elapsed) => Err(GitError::Timeout {
            op,
            secs: limit.as_secs(),
        }),
    }
}

/// The [`GitError::Failed`] a non-zero exit deserves: `git commit` reports "nothing to commit" on
/// stdout, so stdout stands in when stderr is bare.
fn failed(op: &'static str, output: &std::process::Output) -> GitError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = if stderr.trim().is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    GitError::Failed {
        op,
        status: output.status.to_string(),
        message,
    }
}

/// [`git`], with `input` written to the child's stdin.
///
/// Exists for one caller: `git hash-object --stdin`, which is how the freeze learns what git would
/// store for a file **without letting git open that file itself**. The bytes are read first, through
/// the `openat`/`O_NOFOLLOW` route that refuses to follow a symlink, and only then handed over —
/// passing the path to `hash-object` instead would have git read through any symlink in it.
async fn git_stdin<I, S>(
    op: &'static str,
    cwd: &Path,
    args: I,
    input: &[u8],
) -> Result<GitOut, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    use tokio::io::AsyncWriteExt as _;

    let mut command = git_command(op, cwd)?;
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|source| GitError::Io { op, source })?;
    let mut stdin = child.stdin.take().ok_or_else(|| GitError::Io {
        op,
        source: std::io::Error::other("no stdin pipe"),
    })?;

    let limit = git_op_timeout();
    let bytes = input.to_vec();
    let feed = async move {
        stdin.write_all(&bytes).await?;
        stdin.shutdown().await
    };
    let run = async {
        // The write and the wait run together: a filter that reads its whole input before writing
        // any output would deadlock if the pipe were filled first and drained afterwards.
        let (written, output) = tokio::join!(feed, child.wait_with_output());
        written.map_err(|source| GitError::Io { op, source })?;
        output.map_err(|source| GitError::Io { op, source })
    };
    let output = match tokio::time::timeout(limit, run).await {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(GitError::Timeout {
                op,
                secs: limit.as_secs(),
            })
        }
    };

    if !output.status.success() {
        return Err(failed(op, &output));
    }
    Ok(GitOut::new(output))
}

/// The timeout one git call gets.
///
/// Production always uses [`GIT_OP_TIMEOUT`]. **Test-only surface**: in a debug build the
/// `ACP_TEST_GIT_TIMEOUT_MS` environment variable overrides it, which is how `tests/git.rs` proves
/// the timeout path against a sleeping `git` shim in ~1 s instead of 30 s. The gate is
/// `cfg(debug_assertions)` rather than `cfg(test)` on purpose: an integration test links the
/// library compiled *without* `cfg(test)`, so `cfg(test)` would leave the override dead. A release
/// build (`cargo build --release`) compiles the branch out entirely, so the shipped `acp` binary
/// has no environment-driven way to shorten a git timeout.
fn git_op_timeout() -> Duration {
    #[cfg(debug_assertions)]
    {
        if let Some(ms) = std::env::var(TEST_TIMEOUT_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|ms| *ms > 0)
        {
            return Duration::from_millis(ms);
        }
    }
    GIT_OP_TIMEOUT
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// A 40-character lowercase hex object name — hand-written, no `regex`.
fn is_sha40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn checked_sha(op: &'static str, candidate: &str) -> Result<String, GitError> {
    if is_sha40(candidate) {
        Ok(candidate.to_string())
    } else {
        Err(GitError::InvalidRef {
            op,
            value: candidate.to_string(),
        })
    }
}

/// Drop the trailing newline git puts after single-value output, without touching the value itself.
fn trim_eol(s: &str) -> &str {
    s.trim_end_matches(['\n', '\r'])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(cwd: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn retirement_repo() -> (tempfile::TempDir, PathBuf, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        std::fs::create_dir(dir.path().join("state")).expect("mkdir state");
        std::fs::create_dir(&repo).expect("mkdir repo");
        command(&repo, &["init"]);
        command(&repo, &["config", "user.name", "ACP Test"]);
        command(&repo, &["config", "user.email", "acp@example.invalid"]);
        std::fs::write(repo.join(".gitignore"), "ignored.txt\n").expect("gitignore");
        std::fs::write(repo.join("tracked.txt"), "recorded\n").expect("tracked");
        command(&repo, &["add", ".gitignore", "tracked.txt"]);
        command(&repo, &["commit", "-m", "base"]);
        let sha = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&repo)
            .output()
            .expect("rev-parse");
        (
            dir,
            repo,
            String::from_utf8(sha.stdout).expect("utf8").trim().into(),
        )
    }

    fn add_retirement_worktree(repo: &Path, path: &Path, branch: &str, sha: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("worktree parent");
        let output = std::process::Command::new("git")
            .args(["worktree", "add", "-b", branch])
            .arg(path)
            .arg(sha)
            .current_dir(repo)
            .output()
            .expect("add worktree");
        assert!(
            output.status.success(),
            "git worktree add: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn retirement_accepts_repository_aliases_but_refuses_interior_redirects() {
        let (fixture, repo, sha) = retirement_repo();
        let store = fixture.path().join("state");
        let branch = "acp/run/alias";
        let suffix = Path::new(".acp/worktrees/run/alias");
        let worktree = repo.join(suffix);
        add_retirement_worktree(&repo, &worktree, branch, &sha);
        let alias = fixture.path().join("repo-alias");
        std::os::unix::fs::symlink(&repo, &alias).unwrap();
        prepare_retirement(
            &repo,
            &alias.join(suffix),
            &sha,
            branch,
            &store,
            "run",
            "alias",
        )
        .await
        .expect("alternate spelling of the same repository root");
        let redirect = repo.join(".acp/worktrees/run/redirect");
        std::os::unix::fs::symlink(&worktree, &redirect).unwrap();
        assert!(
            prepare_retirement(&repo, &redirect, &sha, branch, &store, "run", "alias")
                .await
                .is_err()
        );
        assert!(worktree.exists());
    }

    #[tokio::test]
    async fn retirement_refuses_overlapping_state_and_untrusted_registration_receipts() {
        let (fixture, repo, sha) = retirement_repo();
        let store = fixture.path().join("state");
        let worktree = repo.join(".acp/worktrees/run/owned");
        let branch = "acp/run/owned";
        add_retirement_worktree(&repo, &worktree, branch, &sha);
        let overlapping = repo.join(".acp/state");
        std::fs::create_dir_all(&overlapping).expect("overlapping state fixture");
        let error =
            prepare_retirement(&repo, &worktree, &sha, branch, &overlapping, "run", "owned")
                .await
                .expect_err("repository-controlled retirement metadata is refused");
        assert!(
            error.to_string().contains("overlaps repository-controlled"),
            "{error}"
        );

        let mut ticket = prepare_retirement(&repo, &worktree, &sha, branch, &store, "run", "owned")
            .await
            .expect("trusted ticket");
        ticket.git_admin_name = "../another-registration".into();
        ticket.trash_path = Some(fixture.path().join("fixture-trash/owned"));
        ticket.git_quarantine_path =
            Some(retirement_identity(&store, "run", "owned").with_file_name("owned.git-admin"));
        save_retirement_identity(&store, "run", "owned", &ticket)
            .await
            .expect("tampered receipt fixture");
        let error = retirement_handoff_planned(&store, &repo, "run", "owned")
            .expect_err("receipt cannot redirect the Git registration");
        assert!(
            error
                .to_string()
                .contains("invalid Git registration identity"),
            "{error}"
        );
        assert!(
            worktree.exists(),
            "the registered tree and lock-bearing admin directory survive"
        );
    }

    #[tokio::test]
    async fn retirement_moves_to_fixture_trash_preserves_fd_and_only_deregisters_target() {
        let (dir, repo, sha) = retirement_repo();
        let store = dir.path().join("state");
        let branch = "acp/run/lineage";
        let worktree = repo.join(".acp/worktrees/run/lineage");
        add_retirement_worktree(&repo, &worktree, branch, &sha);
        let offline = repo.join(".acp/worktrees/run/offline");
        add_retirement_worktree(&repo, &offline, "acp/run/offline", &sha);
        let offline_saved = dir.path().join("offline-saved");
        std::fs::rename(&offline, &offline_saved).expect("make unrelated registration offline");
        let open =
            std::fs::File::open(worktree.join("tracked.txt")).expect("open before Trash handoff");
        let trash = dir.path().join("fixture-trash");
        std::fs::create_dir(&trash).expect("fixture Trash");
        let destination = trash.join("lineage");
        let ticket = prepare_retirement(&repo, &worktree, &sha, branch, &store, "run", "lineage")
            .await
            .expect("prepare");
        let result = quarantine_and_remove_worktree(
            &repo,
            &worktree,
            &sha,
            &store,
            branch,
            RetirementTarget {
                run: "run",
                lineage: "lineage",
                fixture_trash: Some(&destination),
            },
            Some(ticket),
        )
        .await
        .expect("move to fixture Trash");
        assert_eq!(result.preserved_ref, "refs/acp/retained/run/lineage");
        assert_eq!(result.restore_path, destination);
        assert!(!result.disk_space_reclaimed);
        assert!(!worktree.exists());
        assert_eq!(
            std::fs::read_to_string(destination.join("tracked.txt")).unwrap(),
            "recorded\n"
        );
        let mut from_fd = String::new();
        use std::io::Read as _;
        (&open)
            .read_to_string(&mut from_fd)
            .expect("open descriptor survives rename");
        assert_eq!(from_fd, "recorded\n");
        let listed = std::process::Command::new("git")
            .args(["worktree", "list", "--porcelain"])
            .current_dir(&repo)
            .output()
            .expect("list registrations");
        let listed = String::from_utf8_lossy(&listed.stdout);
        assert!(!listed.contains(&worktree.to_string_lossy().to_string()));
        assert!(
            listed.contains(&offline.to_string_lossy().to_string()),
            "unrelated offline registration survives"
        );
        assert!(retirement_complete(&store, &repo, "run", "lineage"));
        let repeated = quarantine_and_remove_worktree(
            &repo,
            &worktree,
            &sha,
            &store,
            branch,
            RetirementTarget {
                run: "run",
                lineage: "lineage",
                fixture_trash: Some(&destination),
            },
            None,
        )
        .await
        .expect("repeat verifies the retained item");
        assert_eq!(repeated.restore_path, destination);
        std::fs::create_dir_all(&worktree).expect("reuse old path");
        std::fs::write(worktree.join("new-owner-data"), "keep\n").expect("new path data");
        let error = prepare_retirement(&repo, &worktree, &sha, branch, &store, "run", "lineage")
            .await
            .expect_err("a repeat cannot mistake a reused path for the retired tree");
        assert!(error.to_string().contains("reused"), "{error}");
        assert!(worktree.join("new-owner-data").exists());
    }

    #[tokio::test]
    async fn retirement_restart_recovers_each_irreversible_handoff_boundary() {
        let (fixture, repo, sha) = retirement_repo();
        let store = fixture.path().join("state");
        let trash = fixture.path().join("fixture-trash");
        std::fs::create_dir(&trash).expect("fixture Trash");

        for (name, registration_already_moved) in
            [("after-tree-move", false), ("after-admin-move", true)]
        {
            let branch = format!("acp/run/{name}");
            let worktree = repo.join(".acp/worktrees/run").join(name);
            add_retirement_worktree(&repo, &worktree, &branch, &sha);
            let destination = trash.join(name);
            let mut ticket =
                prepare_retirement(&repo, &worktree, &sha, &branch, &store, "run", name)
                    .await
                    .expect("prepare restart fixture");
            let quarantine = registration_recovery_path(&ticket.common_dir, "run", name);
            assert!(
                !quarantine.starts_with(ticket.common_dir.join("worktrees")),
                "registration recovery is outside Git's registered-worktrees directory",
            );
            ticket.trash_path = Some(destination.clone());
            ticket.git_quarantine_path = Some(quarantine.clone());
            save_retirement_identity(&store, "run", name, &ticket)
                .await
                .expect("persist plan before move");
            move_to_fixture_trash(&worktree, &destination, ticket.root_dev, ticket.root_ino)
                .expect("simulate process death after tree move");
            if registration_already_moved {
                let journal = registration_run_dir(&ticket.common_dir, "run", true)
                    .await
                    .expect("bound journal");
                let git_dir =
                    derived_git_dir(&ticket.common_dir, &ticket).expect("derived registration");
                move_registration_to_journal(
                    &git_dir,
                    journal.as_fd(),
                    quarantine.parent().unwrap(),
                    quarantine.file_name().unwrap(),
                    ticket.git_dir_dev,
                    ticket.git_dir_ino,
                )
                .expect("simulate process death after registration move");
            }

            let recovered = quarantine_and_remove_worktree(
                &repo,
                &worktree,
                &sha,
                &store,
                &branch,
                RetirementTarget {
                    run: "run",
                    lineage: name,
                    fixture_trash: Some(&destination),
                },
                None,
            )
            .await
            .expect("restart completes from durable locations");
            assert_eq!(recovered.restore_path, destination);
            assert_eq!(
                std::fs::metadata(quarantine.parent().unwrap())
                    .expect("Git-common recovery journal")
                    .dev(),
                std::fs::metadata(&ticket.common_dir)
                    .expect("Git common directory")
                    .dev(),
                "registration recovery stays on Git's filesystem",
            );
            assert!(retirement_complete(&store, &repo, "run", name));
            assert!(
                !derived_git_dir(&ticket.common_dir, &ticket)
                    .unwrap()
                    .exists(),
                "selected registration no longer exists"
            );
        }

        let completed = trash.join("after-tree-move");
        std::fs::remove_dir_all(&completed).expect("simulate a human emptying completed Trash");
        let repeated = quarantine_and_remove_worktree(
            &repo,
            &repo.join(".acp/worktrees/run/after-tree-move"),
            &sha,
            &store,
            "acp/run/after-tree-move",
            RetirementTarget {
                run: "run",
                lineage: "after-tree-move",
                fixture_trash: Some(&completed),
            },
            None,
        )
        .await
        .expect("completed handoff distinguishes an emptied Trash item");
        assert!(repeated.disk_space_reclaimed);
    }

    #[tokio::test]
    async fn legacy_interrupted_receipt_fails_closed_without_moving_registration() {
        let (fixture, repo, sha) = retirement_repo();
        let store = fixture.path().join("state");
        let trash = fixture.path().join("fixture-trash");
        std::fs::create_dir(&trash).expect("fixture Trash");

        let migratable = repo.join(".acp/worktrees/run/legacy-planned");
        let migratable_branch = "acp/run/legacy-planned";
        add_retirement_worktree(&repo, &migratable, migratable_branch, &sha);
        let mut old_plan = prepare_retirement(
            &repo,
            &migratable,
            &sha,
            migratable_branch,
            &store,
            "run",
            "legacy-planned",
        )
        .await
        .expect("prepare old planned receipt");
        old_plan.version = 1;
        old_plan.trash_path = Some(trash.join("obsolete-plan"));
        old_plan.git_quarantine_path = Some(
            retirement_identity(&store, "run", "legacy-planned")
                .with_file_name("legacy-planned.git-admin"),
        );
        save_retirement_identity(&store, "run", "legacy-planned", &old_plan)
            .await
            .expect("persist old pre-move plan");
        let migrated = prepare_retirement(
            &repo,
            &migratable,
            &sha,
            migratable_branch,
            &store,
            "run",
            "legacy-planned",
        )
        .await
        .expect("registered identity safely migrates the plan");
        assert_eq!(migrated.version, RETIREMENT_RECEIPT_VERSION);
        assert!(migrated.trash_path.is_none());
        assert!(migrated.git_quarantine_path.is_none());
        let migrated_destination = trash.join("migrated");
        quarantine_and_remove_worktree(
            &repo,
            &migratable,
            &sha,
            &store,
            migratable_branch,
            RetirementTarget {
                run: "run",
                lineage: "legacy-planned",
                fixture_trash: Some(&migrated_destination),
            },
            Some(migrated),
        )
        .await
        .expect("migrated pre-move plan completes");
        assert!(migrated_destination.join("tracked.txt").exists());

        let worktree = repo.join(".acp/worktrees/run/legacy");
        let branch = "acp/run/legacy";
        add_retirement_worktree(&repo, &worktree, branch, &sha);
        let destination = trash.join("legacy");
        let mut ticket =
            prepare_retirement(&repo, &worktree, &sha, branch, &store, "run", "legacy")
                .await
                .expect("prepare legacy fixture");
        let git_dir = derived_git_dir(&ticket.common_dir, &ticket).expect("registration");
        ticket.version = 1;
        ticket.trash_path = Some(destination.clone());
        ticket.git_quarantine_path =
            Some(retirement_identity(&store, "run", "legacy").with_file_name("legacy.git-admin"));
        save_retirement_identity(&store, "run", "legacy", &ticket)
            .await
            .expect("persist old receipt");
        move_to_fixture_trash(&worktree, &destination, ticket.root_dev, ticket.root_ino)
            .expect("simulate old interruption after tree move");

        let error = quarantine_and_remove_worktree(
            &repo,
            &worktree,
            &sha,
            &store,
            branch,
            RetirementTarget {
                run: "run",
                lineage: "legacy",
                fixture_trash: Some(&destination),
            },
            None,
        )
        .await
        .expect_err("an old receipt cannot authorize registration movement");
        assert!(error.to_string().contains("legacy"), "{error}");
        assert!(destination.join("tracked.txt").exists());
        assert!(git_dir.is_dir(), "the Git registration remains untouched");
    }

    #[tokio::test]
    async fn retirement_preserves_ignored_content_and_a_substituted_worktree() {
        let (dir, repo, sha) = retirement_repo();
        let store = dir.path().join("state");
        let dirty = repo.join(".acp/worktrees/run/dirty");
        add_retirement_worktree(&repo, &dirty, "acp/run/dirty", &sha);
        std::fs::write(dirty.join("ignored.txt"), "user data\n").expect("ignored user data");
        let error =
            prepare_retirement(&repo, &dirty, &sha, "acp/run/dirty", &store, "run", "dirty")
                .await
                .expect_err("ignored content refuses retirement");
        assert!(error.to_string().contains("ignored content"), "{error}");
        assert_eq!(
            std::fs::read_to_string(dirty.join("ignored.txt")).expect("preserved"),
            "user data\n"
        );

        let modified = repo.join(".acp/worktrees/run/modified");
        add_retirement_worktree(&repo, &modified, "acp/run/modified", &sha);
        std::fs::write(modified.join("tracked.txt"), "human edit\n").expect("modified user data");
        let error = prepare_retirement(
            &repo,
            &modified,
            &sha,
            "acp/run/modified",
            &store,
            "run",
            "modified",
        )
        .await
        .expect_err("modified content refuses retirement");
        assert!(error.to_string().contains("modified"), "{error}");
        assert_eq!(
            std::fs::read_to_string(modified.join("tracked.txt")).expect("preserved"),
            "human edit\n"
        );

        let original = repo.join(".acp/worktrees/run/original");
        let substitute = repo.join(".acp/worktrees/run/substitute");
        add_retirement_worktree(&repo, &original, "acp/run/original", &sha);
        add_retirement_worktree(&repo, &substitute, "acp/run/substitute", &sha);
        let ticket = prepare_retirement(
            &repo,
            &original,
            &sha,
            "acp/run/original",
            &store,
            "run",
            "original",
        )
        .await
        .expect("prepare original");
        let moved = repo.join(".acp/worktrees/run/moved-original");
        tokio::fs::rename(&original, &moved)
            .await
            .expect("move original away");
        tokio::fs::rename(&substitute, &original)
            .await
            .expect("substitute recorded path");
        let error = quarantine_and_remove_worktree(
            &repo,
            &original,
            &sha,
            &store,
            "acp/run/original",
            RetirementTarget::new("run", "original"),
            Some(ticket),
        )
        .await
        .expect_err("substitution is rejected");
        assert!(error.to_string().contains("substituted"), "{error}");
        assert!(
            original.join("tracked.txt").exists(),
            "the substituted host tree was not deleted"
        );
        assert!(
            moved.join("tracked.txt").exists(),
            "the original ACP tree was not deleted either"
        );
    }

    #[test]
    fn retirement_bound_move_refuses_a_mismatched_durable_identity() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let source_parent = fixture.path().join("source");
        let destination_parent_path = fixture.path().join("destination");
        let source = source_parent.join("tree");
        let other = source_parent.join("other");
        std::fs::create_dir_all(&source).expect("source tree");
        std::fs::create_dir(&other).expect("other tree");
        std::fs::create_dir(&destination_parent_path).expect("destination parent");
        std::fs::write(source.join("user-data"), "preserve\n").expect("source data");
        let other_metadata = std::fs::metadata(&other).expect("other identity");
        let destination_parent = open_bound_directory(&destination_parent_path, "retirement_test")
            .expect("bound destination");

        let error = move_directory_no_replace(
            &source,
            destination_parent.as_fd(),
            &destination_parent_path,
            OsStr::new("retired-tree"),
            other_metadata.dev(),
            other_metadata.ino(),
            "retirement_test",
        )
        .expect_err("a ticket for another inode cannot move the source leaf");

        assert!(error.to_string().contains("wrong identity"), "{error}");
        assert_eq!(
            std::fs::read_to_string(source.join("user-data")).expect("preserved source data"),
            "preserve\n",
        );
        assert!(!destination_parent_path.join("retired-tree").exists());
    }

    #[tokio::test]
    async fn retirement_refuses_redirected_journals_and_preserves_post_validation_edits() {
        let (fixture, repo, sha) = retirement_repo();
        let store = fixture.path().join("state");
        let redirected = repo.join(".acp/worktrees/run/redirected-journal");
        let branch = "acp/run/redirected-journal";
        add_retirement_worktree(&repo, &redirected, branch, &sha);
        let ticket = prepare_retirement(
            &repo,
            &redirected,
            &sha,
            branch,
            &store,
            "run",
            "redirected-journal",
        )
        .await
        .expect("prepare redirected journal fixture");
        let outside = fixture.path().join("outside");
        std::fs::create_dir(&outside).expect("outside directory");
        let sentinel = outside.join("sentinel");
        std::fs::write(&sentinel, "do not overwrite\n").expect("outside sentinel");
        let bound_retired = store.join("retired-bound");
        std::fs::rename(store.join("retired"), &bound_retired)
            .expect("move the durable fixture journal aside");
        std::os::unix::fs::symlink(&outside, store.join("retired")).expect("hostile retired link");
        let error = quarantine_and_remove_worktree(
            &repo,
            &redirected,
            &sha,
            &store,
            branch,
            RetirementTarget::new("run", "redirected-journal"),
            Some(ticket),
        )
        .await
        .expect_err("a redirected retirement directory is refused");
        assert!(
            error.to_string().contains("retirement_directory"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(&sentinel).expect("sentinel survives"),
            "do not overwrite\n"
        );
        assert!(
            redirected.exists(),
            "the worktree survives a redirected journal"
        );
        std::fs::remove_file(store.join("retired")).expect("remove fixture link");
        std::fs::rename(bound_retired, store.join("retired"))
            .expect("restore the durable fixture journal");

        let changed = repo.join(".acp/worktrees/run/changed-after-check");
        let changed_branch = "acp/run/changed-after-check";
        add_retirement_worktree(&repo, &changed, changed_branch, &sha);
        let ticket = prepare_retirement(
            &repo,
            &changed,
            &sha,
            changed_branch,
            &store,
            "run",
            "changed-after-check",
        )
        .await
        .expect("prepare changed fixture");
        std::fs::write(changed.join("tracked.txt"), "late user edit\n").expect("late edit");
        let trash = fixture.path().join("fixture-trash");
        std::fs::create_dir(&trash).expect("fixture Trash");
        let destination = trash.join("changed");
        let error = quarantine_and_remove_worktree(
            &repo,
            &changed,
            &sha,
            &store,
            changed_branch,
            RetirementTarget {
                run: "run",
                lineage: "changed-after-check",
                fixture_trash: Some(&destination),
            },
            Some(ticket),
        )
        .await
        .expect_err("a post-validation edit is preserved");
        assert!(error.to_string().contains("content changed"), "{error}");
        assert_eq!(
            std::fs::read_to_string(changed.join("tracked.txt")).expect("late edit survives"),
            "late user edit\n"
        );
        assert!(!destination.exists());

        let collision = repo.join(".acp/worktrees/run/collision");
        let collision_branch = "acp/run/collision";
        add_retirement_worktree(&repo, &collision, collision_branch, &sha);
        let ticket = prepare_retirement(
            &repo,
            &collision,
            &sha,
            collision_branch,
            &store,
            "run",
            "collision",
        )
        .await
        .expect("prepare collision fixture");
        let occupied = trash.join("occupied");
        std::fs::create_dir(&occupied).expect("occupied fixture Trash name");
        std::fs::write(occupied.join("sentinel"), "existing\n").expect("collision sentinel");
        let _error = quarantine_and_remove_worktree(
            &repo,
            &collision,
            &sha,
            &store,
            collision_branch,
            RetirementTarget {
                run: "run",
                lineage: "collision",
                fixture_trash: Some(&occupied),
            },
            Some(ticket),
        )
        .await
        .expect_err("Trash handoff never replaces an existing item");
        assert!(collision.join("tracked.txt").is_file());
        assert_eq!(
            std::fs::read_to_string(occupied.join("sentinel")).unwrap(),
            "existing\n"
        );
    }

    #[test]
    fn source_inventory_limits_names_during_directory_read() {
        let repo = tempfile::tempdir().unwrap();
        for name in ["a", "b"] {
            std::fs::write(repo.path().join(name), []).unwrap();
        }
        let read = |paths_left, bytes_left| {
            let root = open_root_dir(repo.path()).unwrap();
            let mut state = InventoryState {
                digest: Sha256::new(),
                bytes_left,
                paths_left,
                top: repo.path().into(),
                visited: HashSet::new(),
            };
            inventory_directory_names(&root, true, 0, &mut state)
        };
        assert_eq!(read(2, 2).unwrap(), [b"a", b"b"]);
        assert!(read(1, 2).unwrap_err().to_string().contains("path count"));
        assert!(read(2, 1).unwrap_err().to_string().contains("bytes"));
    }

    #[tokio::test]
    async fn source_inventory_bounds_index_paths_before_checkout_accounting() {
        let repo = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(args)
                .output()
                .unwrap()
                .status
                .success());
        };
        git(&["init", "-q"]);
        std::fs::write(repo.path().join("a"), []).unwrap();
        std::fs::write(repo.path().join("b"), []).unwrap();
        git(&["add", "a", "b"]);

        // Both limits reject while ingesting the index, before the root or checkout walk can
        // consume either budget. In particular, retaining the second key is never necessary.
        let count = source_inventory_hash_with_limits(repo.path(), 1, 2)
            .await
            .unwrap_err();
        assert!(count.to_string().contains("path count limit"));
        let bytes = source_inventory_hash_with_limits(repo.path(), 2, 1)
            .await
            .unwrap_err();
        assert!(bytes.to_string().contains("bytes"));
    }

    #[tokio::test]
    async fn source_inventory_charges_tracked_paths_once_and_keeps_deletions() {
        let repo = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(args)
                .output()
                .unwrap()
                .status
                .success());
        };
        git(&["init", "-q"]);
        std::fs::write(repo.path().join("a"), []).unwrap();
        std::fs::write(repo.path().join("b"), []).unwrap();
        git(&["add", "a", "b"]);

        // Root + two tracked files, with one byte per file name. Charging index ingestion as
        // inventory accounting as well as the walk would exceed both exact limits.
        let present = source_inventory_hash_with_limits(repo.path(), 3, 2)
            .await
            .expect("tracked checkout paths are charged once");
        std::fs::remove_file(repo.path().join("b")).unwrap();
        let deleted = source_inventory_hash_with_limits(repo.path(), 3, 2)
            .await
            .expect("the leftover index entry is charged once as a deletion");
        assert_ne!(present, deleted, "the deletion marker remains inventory data");
    }

    #[tokio::test]
    async fn source_inventory_charges_pending_names_across_directories_and_deletions() {
        let repo = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(args)
                .output()
                .unwrap()
                .status
                .success());
        };
        git(&["init", "-q"]);
        std::fs::create_dir(repo.path().join("a")).unwrap();
        std::fs::write(repo.path().join("a/b"), []).unwrap();
        std::fs::write(repo.path().join("z"), []).unwrap();
        std::fs::write(repo.path().join("gone"), []).unwrap();
        git(&["add", "gone"]);
        std::fs::remove_file(repo.path().join("gone")).unwrap();
        // Root, a, a/b, z and the tracked deletion. The raw path lengths total nine.
        let exact = source_inventory_hash_with_limits(repo.path(), 5, 9)
            .await
            .unwrap();
        assert_eq!(exact, source_inventory_hash(repo.path()).await.unwrap());
        let count = source_inventory_hash_with_limits(repo.path(), 4, 9)
            .await
            .unwrap_err();
        assert!(count.to_string().contains("path count limit"));
        let bytes = source_inventory_hash_with_limits(repo.path(), 5, 8)
            .await
            .unwrap_err();
        assert!(bytes.to_string().contains("bytes"));
    }

    #[test]
    fn sha_validation_is_strict() {
        assert!(is_sha40(&"a".repeat(40)));
        assert!(is_sha40("f51121132ff429b2ceedafd4843524223e2e81c1"));
        assert!(!is_sha40(&"A".repeat(40)), "uppercase is rejected");
        assert!(!is_sha40(&"a".repeat(39)));
        assert!(!is_sha40(&"a".repeat(41)));
        assert!(!is_sha40("../etc/passwd"));
        assert!(!is_sha40(""));
    }

    #[test]
    fn acp_trailer_lines_are_recognized() {
        assert!(is_acp_trailer_line("Acp-Gate-Id: 1234"));
        assert!(is_acp_trailer_line("Acp-Run-Id:1234"));
        assert!(is_acp_trailer_line("  Acp-Gate-Id: 1234"));
        assert!(is_acp_trailer_line("acp-gate-id: 1234"));
        assert!(is_acp_trailer_line("Acp-Gate-Id : 1234"));

        assert!(!is_acp_trailer_line("Acp-Id: 1234"), "no <word> segment");
        assert!(!is_acp_trailer_line("Acp-Gate-Id"), "no separator");
        assert!(!is_acp_trailer_line("Signed-off-by: someone"));
        assert!(!is_acp_trailer_line("mentions Acp-Gate-Id: mid-line"));
        assert!(!is_acp_trailer_line("Acp-Gate Id: 1234"), "space in token");
        assert!(!is_acp_trailer_line(""));
    }

    #[test]
    fn subject_is_one_line_and_byte_bounded() {
        assert_eq!(subject_line("fix the thing"), "fix the thing");
        assert_eq!(subject_line("first\nsecond"), "first");
        assert_eq!(subject_line("tab\there"), "tab here");
        assert_eq!(subject_line("   "), FALLBACK_SUBJECT);

        let cjk = "実装".repeat(100); // 3 bytes per char
        let subject = subject_line(&cjk);
        assert!(subject.len() <= MAX_SUBJECT_BYTES);
        assert_eq!(subject.len() % 3, 0, "never split a codepoint");
        assert_eq!(subject.chars().count(), 24);
    }

    #[test]
    fn body_loses_forged_trailers_only() {
        let msg = CommitMessage {
            title: "integrate task 7".to_string(),
            body: "did the work\nAcp-Gate-Id: forged\nSigned-off-by: nobody".to_string(),
        };
        let built = build_commit_message(&msg);
        assert!(built.starts_with("integrate task 7\n\n"));
        assert!(!built.contains("forged"));
        assert!(built.contains("did the work"));
        assert!(built.contains("Signed-off-by: nobody"));
    }

    #[test]
    fn diff_line_counting_ignores_file_headers() {
        let diff = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n-old\n+new\n+more\n";
        assert_eq!(count_diff_lines(diff.as_bytes()), (2, 1));
    }

    /// A refusal to traverse a symlink. `O_NOFOLLOW` reports `ELOOP`; combined with `O_DIRECTORY`,
    /// the BSD/macOS kernels report `ENOTDIR` for the same refusal, so both count.
    fn is_symlink_refusal(err: &std::io::Error) -> bool {
        matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR))
    }

    /// Reads a whole file through the fd-based route, for the `open_under_root` tests.
    fn read_through_fd(root: &Path, rel: &str) -> std::io::Result<String> {
        use std::io::Read;

        let root_fd = open_root_dir(root)?;
        let mut file = open_under_root(root_fd.as_fd(), rel)?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text)
    }

    #[test]
    fn open_under_root_reads_a_nested_regular_file() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join("a/b")).expect("mkdir");
        std::fs::write(root.path().join("a/b/note.txt"), "hello\n").expect("write");

        assert_eq!(
            read_through_fd(root.path(), "a/b/note.txt").expect("read"),
            "hello\n"
        );
    }

    #[test]
    fn open_under_root_refuses_a_leaf_symlink() {
        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        let secret = outside.path().join("auth.json");
        std::fs::write(&secret, "SECRET").expect("write");
        std::os::unix::fs::symlink(&secret, root.path().join("leak.txt")).expect("symlink");

        let err = read_through_fd(root.path(), "leak.txt").expect_err("must not follow the link");
        assert!(
            is_symlink_refusal(&err),
            "O_NOFOLLOW rejects the leaf: {err}"
        );
    }

    #[test]
    fn open_under_root_refuses_a_parent_swapped_for_a_symlink() {
        // The exact TOCTOU Codex flagged, made deterministic: classify the path first, then swap a
        // *directory component* for a symlink to somewhere outside, then read. A path-based reopen
        // would follow the new link; the fd route cannot.
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join("a/b")).expect("mkdir");
        std::fs::write(root.path().join("a/b/secret.txt"), "benign\n").expect("write");

        let canonical = root.path().canonicalize().expect("canonicalize");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let verdict = runtime.block_on(classify_untracked(
            root.path(),
            &canonical,
            "a/b/secret.txt",
        ));
        assert!(
            matches!(verdict, Untracked::Regular),
            "classification passes before the swap"
        );
        assert_eq!(
            read_through_fd(root.path(), "a/b/secret.txt").expect("read"),
            "benign\n"
        );

        // The attacker's move, between check and read.
        let outside = tempfile::tempdir().expect("tempdir");
        std::fs::write(outside.path().join("secret.txt"), "SUPER-SECRET\n").expect("write");
        std::fs::remove_dir_all(root.path().join("a/b")).expect("rmdir");
        std::os::unix::fs::symlink(outside.path(), root.path().join("a/b")).expect("symlink");

        let err = read_through_fd(root.path(), "a/b/secret.txt")
            .expect_err("a symlinked parent must not be traversed");
        assert!(
            is_symlink_refusal(&err),
            "openat on the swapped component fails: {err}"
        );
        // And the same path read the naive way *would* have leaked, which is why this matters.
        assert_eq!(
            std::fs::read_to_string(root.path().join("a/b/secret.txt")).expect("read"),
            "SUPER-SECRET\n"
        );
    }

    #[test]
    fn open_under_root_refuses_a_fifo_and_a_traversal_path() {
        let root = tempfile::tempdir().expect("tempdir");
        let fifo = CString::new(root.path().join("pipe").as_os_str().as_bytes()).expect("cstring");
        // SAFETY: `fifo` is a valid NUL-terminated path in a fresh temp directory.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let err = read_through_fd(root.path(), "pipe").expect_err("a fifo is not a regular file");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        let err = read_through_fd(root.path(), "../escape").expect_err("no traversal");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn path_sanitization_keeps_only_absolute_entries() {
        let entries = absolute_path_entries(OsStr::new(":/usr/bin:.:relative/bin:/bin:"));
        assert_eq!(
            entries,
            vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")],
            "empty, `.` and relative entries are dropped — they mean the worker's worktree"
        );
        assert!(absolute_path_entries(OsStr::new("")).is_empty());
        assert!(absolute_path_entries(OsStr::new(".:..:sub/dir")).is_empty());
    }

    #[test]
    fn resolve_program_only_looks_in_absolute_entries() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let planted = dir.path().join("git");
        std::fs::write(&planted, "#!/bin/sh\nexit 0\n").expect("write");
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::write(dir.path().join("not-executable"), "x").expect("write");

        let absolute = OsString::from(format!(":.:{}", dir.path().display()));
        assert_eq!(
            resolve_program(&absolute_path_entries(&absolute), "git").as_deref(),
            Some(planted.as_path())
        );
        assert_eq!(
            resolve_program(&absolute_path_entries(&absolute), "not-executable"),
            None,
            "a non-executable file is not a program"
        );

        // The very same directory reached through a relative entry is never searched.
        let relative = OsString::from(":.:relative/bin");
        assert_eq!(
            resolve_program(&absolute_path_entries(&relative), "git"),
            None
        );
    }

    #[test]
    fn timeout_defaults_to_the_constant() {
        // The test-only override is read per call; with the variable unset it is the design's 30 s.
        assert!(std::env::var(TEST_TIMEOUT_ENV).is_err());
        assert_eq!(git_op_timeout(), GIT_OP_TIMEOUT);
    }
}
