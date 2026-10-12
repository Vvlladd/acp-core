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
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::RwLock;
use std::time::Duration;

use globset::GlobSet;
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

/// Error text retained from a streaming git child. The pipe is drained beyond this bound so a
/// noisy child cannot deadlock, but an error cannot make the daemon retain unbounded stderr.
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;

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
pub async fn recovery_status(repo: &Path, worktree: &Path, base_sha: &str) -> Result<String, GitError> {
    let invalid = || GitError::RecoveryInvalid { reason:
        "The preserved draft is missing, redirected, belongs to another repository, or its base commit changed.".into() };
    let canonical_repo = tokio::fs::canonicalize(repo).await.map_err(|_| invalid())?;
    let relative = worktree.strip_prefix(repo).map_err(|_| invalid())?;
    if !relative.starts_with(".acp/worktrees") { return Err(invalid()); }
    let canonical = tokio::fs::canonicalize(worktree).await.map_err(|_| invalid())?;
    // macOS's /var and /tmp aliases may occur above the repository. Links within the draft path
    // still fail: its canonical location must be exactly the same suffix under the real root.
    let top = tokio::fs::canonicalize(repo_root(worktree).await?).await.map_err(|_| invalid())?;
    if canonical != canonical_repo.join(relative) || top != canonical || head_sha(worktree).await? != base_sha {
        return Err(invalid());
    }
    async fn common_dir(path: &Path) -> Result<PathBuf, GitError> {
        let out = git("recovery_repository", path, [tok("rev-parse"), tok("--path-format=absolute"), tok("--git-common-dir")]).await?;
        let dir = PathBuf::from(trim_eol(&out.stdout()));
        tokio::fs::canonicalize(&dir).await.map_err(|source| GitError::Io { op: "recovery_repository", source })
    }
    if common_dir(repo).await? != common_dir(worktree).await? { return Err(invalid()); }
    status_porcelain(worktree).await
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
    let mode = if mode == MODE_EXEC { MODE_EXEC } else { MODE_FILE };
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
        file.write_all(chunk)
            .await
            .map_err(|source| GitError::Io {
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
    let mut committed: Vec<&str> = listed_stdout.split('\0').filter(|p| !p.is_empty()).collect();
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
        Untracked::Symlink { at, target } => render_new_file(rel, NewContent::Symlink { at, target }),
        Untracked::Rejected { reason } => {
            render_new_file(rel, NewContent::Rejected { reason: reason.to_string() })
        }
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
    Symlink { at: String, target: String },
    Rejected { reason: String },
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
    command.args(args).stdin(Stdio::null()).stdout(Stdio::piped());

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
    command.args(args).stdin(Stdio::null()).stdout(Stdio::piped());

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
    command.args(args).stdin(Stdio::null()).stdout(Stdio::piped());

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
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| GitError::Io { op, source: std::io::Error::other("no stdin pipe") })?;

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
