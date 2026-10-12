//! Real-git coverage for `src/workspace/git.rs` (T19), per `reports/03-design.md` Test Strategy.
//!
//! Every test builds its own throwaway repository with `tempfile::TempDir` + `git init` + an empty
//! initial commit and drives the module against the **real** `git` binary — no fakes, no mocks: the
//! whole point of `workspace/git.rs` is that worktree, index and reflog semantics are exactly what
//! the human sees on the command line. The single exception is the timeout test, which shims a
//! sleeping `git` onto `PATH`.
//!
//! That shim, and the `ACP_TEST_GIT_TIMEOUT_MS` override it needs, are **process-global**. Cargo
//! runs the tests in this binary on parallel threads, so `ENV_GUARD` serializes them: real-git tests
//! run through `with_real_git` (shared), the timeout test through `with_shimmed_git` (exclusive),
//! so no other test can observe the sleeping `git` or the shortened timeout.

use std::fs;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use agent_control_plane::workspace::git::{
    self, CommitMessage, GitError, FROZEN_DIFF_TRUNCATION_MARKER, MAX_FROZEN_DIFF_BYTES,
};
use globset::{Glob, GlobSetBuilder};
use tempfile::TempDir;

/// See the module comment: shared for the real-git tests, exclusive for the `PATH`-shim one.
static ENV_GUARD: RwLock<()> = RwLock::new(());

/// Runs one async test body on its own current-thread runtime while holding `ENV_GUARD` shared.
///
/// The guard is taken in *sync* code around `block_on` rather than inside the future, so no lock is
/// ever held across an `await` (`clippy::await_holding_lock`).
fn with_real_git<F, Fut>(body: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let _env = ENV_GUARD
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    block_on(body());
}

/// Same, but exclusive: for the one test that rewrites the process-global `PATH`.
fn with_shimmed_git<F, Fut>(body: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let _env = ENV_GUARD
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    block_on(body());
}

fn block_on<Fut: Future<Output = ()>>(fut: Fut) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(fut);
}

/// Runs real git in `cwd` and returns its stdout, asserting success.
fn run_git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|err| panic!("spawn git {args:?}: {err}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A fresh repository with an identity configured (the module's `commit_all` runs a real commit)
/// and one empty commit, so `HEAD` resolves.
fn init_repo() -> TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    run_git(dir.path(), &["init", "--quiet", "-b", "main"]);
    run_git(dir.path(), &["config", "user.name", "acp-test"]);
    run_git(
        dir.path(),
        &["config", "user.email", "acp-test@example.invalid"],
    );
    run_git(
        dir.path(),
        &["commit", "--quiet", "--allow-empty", "-m", "init"],
    );
    dir
}

/// macOS puts `TempDir`s under `/var`, a symlink to `/private/var`; git reports the resolved path.
fn resolved(path: &Path) -> PathBuf {
    path.canonicalize().expect("canonicalize")
}

const LARGE_TRACKED_BYTES: usize = 20 * 1024 * 1024;

/// Exact-size, line-oriented content whose diff crosses the assembled artifact cap many times.
fn large_tracked_contents() -> Vec<u8> {
    let line = b"replacement tracked content that must remain in the committed blob 0123456789\n";
    let mut bytes = line.repeat(LARGE_TRACKED_BYTES / line.len());
    bytes.extend_from_slice(&line[..LARGE_TRACKED_BYTES - bytes.len()]);
    bytes[LARGE_TRACKED_BYTES - 1] = b'\n';
    assert_eq!(bytes.len(), LARGE_TRACKED_BYTES);
    bytes
}

#[test]
fn worktree_add_and_remove_round_trip() {
    with_real_git(|| async {
        let repo = init_repo();
        let scratch = tempfile::tempdir().expect("tempdir");
        let worktree = scratch.path().join("lineage-1");

        let base = git::resolve_ref(repo.path(), "HEAD")
            .await
            .expect("resolve HEAD");
        git::add_worktree(repo.path(), &worktree, "acp/lineage-1", &base)
            .await
            .expect("add worktree");

        assert!(worktree.join(".git").exists(), "worktree was checked out");
        assert_eq!(git::head_sha(&worktree).await.expect("head"), base);
        assert_eq!(
            git::repo_root(&worktree).await.expect("repo root"),
            resolved(&worktree)
        );
        assert!(run_git(repo.path(), &["worktree", "list"]).contains("acp/lineage-1"));

        git::remove_worktree(repo.path(), &worktree, false)
            .await
            .expect("remove worktree");
        assert!(!worktree.exists(), "worktree directory is gone");
        assert!(!run_git(repo.path(), &["worktree", "list"]).contains("acp/lineage-1"));
    });
}

#[test]
fn undoing_a_worker_commit_keeps_the_work_and_leaves_a_clean_index() {
    with_real_git(|| async {
        let repo = init_repo();
        let scratch = tempfile::tempdir().expect("tempdir");
        let worktree = scratch.path().join("lineage-1");

        let base = git::resolve_ref(repo.path(), "HEAD")
            .await
            .expect("resolve HEAD");
        git::add_worktree(repo.path(), &worktree, "acp/lineage-1", &base)
            .await
            .expect("add worktree");

        // A worker that commits despite being told not to (the `worker_commits` scenario).
        fs::write(worktree.join("feature.txt"), "implemented\n").expect("write");
        run_git(&worktree, &["add", "-A"]);
        run_git(&worktree, &["commit", "--quiet", "-m", "worker commit"]);
        let post = git::head_sha(&worktree).await.expect("post head");
        assert_ne!(
            post, base,
            "HEAD moved — this is what the supervisor detects"
        );

        git::reset_mixed(&worktree, &base)
            .await
            .expect("undo the worker commit");

        assert_eq!(
            git::head_sha(&worktree).await.expect("head after reset"),
            base,
            "HEAD is back at the pre-attempt sha"
        );
        assert_eq!(
            fs::read_to_string(worktree.join("feature.txt")).expect("read"),
            "implemented\n",
            "the worker's file survived"
        );
        let porcelain = git::status_porcelain(&worktree).await.expect("porcelain");
        assert!(
            porcelain.contains("feature.txt"),
            "the change is uncommitted again: {porcelain:?}"
        );
        let changed = git::changed_files(&worktree).await.expect("changed files");
        assert!(changed.iter().any(|c| c.path == "feature.txt"));

        // …and the index is clean, which is what lets the run ever be integrated: an approval
        // refuses to commit on top of anything already staged, so a `--soft` reset here would have
        // wedged every worker-committed run for good (round-3 review, finding 1).
        git::assert_index_clean(&worktree)
            .await
            .expect("the remediation leaves nothing staged");
        assert!(
            changed.iter().any(|c| c.path == "feature.txt" && c.is_untracked()),
            "the worker's new file is untracked again, exactly as if it had never been committed: \
             {changed:?}"
        );
    });
}

#[test]
fn untracked_and_tracked_changes_reach_the_frozen_diff() {
    with_real_git(|| async {
        let repo = init_repo();
        let scratch = tempfile::tempdir().expect("tempdir");
        let worktree = scratch.path().join("lineage-1");

        fs::write(repo.path().join("tracked.txt"), "old\n").expect("write");
        run_git(repo.path(), &["add", "-A"]);
        run_git(repo.path(), &["commit", "--quiet", "-m", "add tracked"]);

        let base = git::resolve_ref(repo.path(), "HEAD")
            .await
            .expect("resolve HEAD");
        git::add_worktree(repo.path(), &worktree, "acp/lineage-1", &base)
            .await
            .expect("add worktree");

        fs::write(worktree.join("tracked.txt"), "new\n").expect("write");
        fs::create_dir_all(worktree.join("Sub")).expect("mkdir");
        fs::write(worktree.join("Sub/App.xcconfig"), "SETTING = 1\n").expect("write");
        fs::write(worktree.join("notes.txt"), "line one\nline two\n").expect("write");

        // An untracked file inside an untracked directory must be listed individually — a collapsed
        // `Sub/` entry would hide `Sub/App.xcconfig` from the denylist.
        let changed = git::changed_files(&worktree).await.expect("changed files");
        let paths: Vec<&str> = changed.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"tracked.txt"), "{paths:?}");
        assert!(paths.contains(&"Sub/App.xcconfig"), "{paths:?}");
        assert!(paths.contains(&"notes.txt"), "{paths:?}");
        assert!(changed
            .iter()
            .find(|c| c.path == "notes.txt")
            .expect("notes.txt entry")
            .is_untracked());

        let porcelain = git::status_porcelain(&worktree).await.expect("porcelain");
        assert!(porcelain.contains("notes.txt"), "{porcelain:?}");

        // `diffs/` does not exist yet: frozen_diff creates the parent directory it is handed.
        let out = scratch.path().join("diffs/attempt-1.patch");
        let stat = git::frozen_diff(&worktree, &out)
            .await
            .expect("frozen diff");
        let patch = fs::read_to_string(&out).expect("read patch");

        assert!(patch.contains("--- a/tracked.txt"), "{patch}");
        assert!(patch.contains("-old"), "{patch}");
        assert!(patch.contains("+new"), "{patch}");
        assert!(patch.contains("+++ b/notes.txt"), "{patch}");
        assert!(patch.contains("+line one"), "{patch}");
        assert!(patch.contains("+line two"), "{patch}");
        assert!(patch.contains("+++ b/Sub/App.xcconfig"), "{patch}");
        assert!(patch.contains("+SETTING = 1"), "{patch}");

        assert!(stat.files.contains(&"Sub/App.xcconfig".to_string()));
        assert!(
            stat.symlinks.is_empty(),
            "ordinary files are inlined, nothing refused: {:?}",
            stat.symlinks
        );
        assert_eq!(stat.added, 4, "new + 2 note lines + the xcconfig line");
        assert_eq!(stat.deleted, 1, "old");
    });
}

#[test]
fn an_untracked_symlink_never_leaks_the_target_contents() {
    with_real_git(|| async {
        let repo = init_repo();
        let scratch = tempfile::tempdir().expect("tempdir");
        let worktree = scratch.path().join("lineage-1");

        let base = git::resolve_ref(repo.path(), "HEAD")
            .await
            .expect("resolve HEAD");
        git::add_worktree(repo.path(), &worktree, "acp/lineage-1", &base)
            .await
            .expect("add worktree");

        // A file the sandboxed worker may not read, but the daemon can — the real threat is
        // `~/.codex/auth.json`; any readable file outside the worktree stands in for it.
        let outside = tempfile::tempdir().expect("tempdir");
        let secret = outside.path().join("auth.json");
        fs::write(&secret, "{\"token\":\"SUPER-SECRET-DO-NOT-LEAK\"}\n").expect("write");
        assert!(
            fs::read_to_string(&secret)
                .expect("read")
                .contains("SUPER-SECRET-DO-NOT-LEAK"),
            "the test process can read it, so an unhardened frozen_diff would have copied it"
        );

        std::os::unix::fs::symlink(&secret, worktree.join("leak.txt")).expect("symlink file");
        std::os::unix::fs::symlink(outside.path(), worktree.join("linkdir")).expect("symlink dir");
        fs::write(worktree.join("real.txt"), "genuine change\n").expect("write");

        let out = scratch.path().join("diffs/attempt-1.patch");
        let stat = git::frozen_diff(&worktree, &out)
            .await
            .expect("frozen diff");
        let patch = fs::read_to_string(&out).expect("read patch");

        assert!(
            !patch.contains("SUPER-SECRET-DO-NOT-LEAK"),
            "the link target's contents must never reach the diff:\n{patch}"
        );
        assert!(patch.contains("+++ b/leak.txt"), "{patch}");
        assert!(
            patch.contains("new file mode 120000"),
            "reported as a symlink: {patch}"
        );
        assert!(
            patch.contains(&secret.display().to_string()),
            "the target path itself is disclosed, only the contents are withheld: {patch}"
        );
        assert!(patch.contains("contents were never read"), "{patch}");

        assert!(stat.symlinks.contains(&"leak.txt".to_string()), "{stat:?}");
        assert!(stat.symlinks.contains(&"linkdir".to_string()), "{stat:?}");

        // A genuine untracked file is still inlined in full.
        assert!(patch.contains("+++ b/real.txt"), "{patch}");
        assert!(patch.contains("+genuine change"), "{patch}");
        assert!(!stat.symlinks.contains(&"real.txt".to_string()), "{stat:?}");
    });
}

#[test]
fn denylist_matches_a_nested_xcconfig_and_misses_a_source_file() {
    let globs = GlobSetBuilder::new()
        .add(Glob::new("**/*.xcconfig").expect("glob"))
        .add(Glob::new("**/Migrations/**").expect("glob"))
        .build()
        .expect("glob set");

    let paths = vec![
        "Sub/App.xcconfig".to_string(),
        "App.swift".to_string(),
        "db/Migrations/001.sql".to_string(),
    ];
    let hits = git::match_denylist(&paths, &globs);

    let hit_paths: Vec<&str> = hits.iter().map(|h| h.path.as_str()).collect();
    assert_eq!(hit_paths, vec!["Sub/App.xcconfig", "db/Migrations/001.sql"]);
    assert_eq!(hits[0].glob_indices, vec![0]);
    assert_eq!(hits[1].glob_indices, vec![1]);
}

#[test]
fn a_forged_acp_trailer_in_the_body_never_reaches_the_commit() {
    with_real_git(|| async {
        let repo = init_repo();
        let gate_id = "11111111-1111-4111-8111-111111111111";
        let run_id = "22222222-2222-4222-8222-222222222222";
        let forged_gate = "99999999-9999-4999-8999-999999999999";

        fs::write(repo.path().join("worker.txt"), "work\n").expect("write");

        // The body is worker-influenced text (a task description). It tries to forge the trailer the
        // control plane reconciles gates on (S7).
        let msg = CommitMessage {
            title: "integrate task 7".to_string(),
            body: format!("worker prose\nAcp-Gate-Id: {forged_gate}\nmore prose"),
        };
        let sha = git::commit_all(
            repo.path(),
            &msg,
            &["worker.txt".to_string()],
            &[("Acp-Gate-Id", gate_id), ("Acp-Run-Id", run_id)],
        )
        .await
        .expect("commit");

        assert_eq!(sha, git::head_sha(repo.path()).await.expect("head"));

        let body = run_git(repo.path(), &["log", "-1", "--format=%B"]);
        assert!(
            !body.contains(forged_gate),
            "forged trailer survived: {body:?}"
        );
        assert_eq!(
            body.matches("Acp-Gate-Id").count(),
            1,
            "exactly one gate trailer: {body:?}"
        );
        assert!(
            body.contains(&format!("Acp-Gate-Id: {gate_id}")),
            "{body:?}"
        );
        assert!(body.contains(&format!("Acp-Run-Id: {run_id}")), "{body:?}");
        assert!(
            body.contains("worker prose"),
            "the rest of the body is kept: {body:?}"
        );
        assert!(body.contains("more prose"), "{body:?}");
        assert_eq!(
            run_git(repo.path(), &["log", "-1", "--format=%s"]).trim(),
            "integrate task 7"
        );

        // Crash-recovery reconciliation finds the commit by its real trailer, and only by that one.
        assert_eq!(
            git::find_commit_by_trailer(repo.path(), "Acp-Gate-Id", gate_id)
                .await
                .expect("lookup"),
            Some(sha)
        );
        assert_eq!(
            git::find_commit_by_trailer(repo.path(), "Acp-Gate-Id", forged_gate)
                .await
                .expect("lookup"),
            None
        );
    });
}

#[test]
fn a_multibyte_title_truncates_on_a_char_boundary() {
    with_real_git(|| async {
        let repo = init_repo();
        fs::write(repo.path().join("worker.txt"), "work\n").expect("write");

        let title = "実装".repeat(100); // 200 chars, 600 bytes
        git::commit_all(
            repo.path(),
            &CommitMessage {
                title: title.clone(),
                body: String::new(),
            },
            &["worker.txt".to_string()],
            &[],
        )
        .await
        .expect("commit");

        let subject = run_git(repo.path(), &["log", "-1", "--format=%s"]);
        let subject = subject.trim_end_matches('\n');
        assert!(subject.len() <= 72, "{} bytes", subject.len());
        assert!(
            title.starts_with(subject),
            "the subject is a prefix of the title, never a split codepoint"
        );
        assert_eq!(subject.chars().count(), 24, "72 bytes / 3 bytes per char");
    });
}

#[test]
fn a_dash_prefixed_ref_is_handed_to_git_rather_than_rejected_here() {
    with_real_git(|| async {
        let repo = init_repo();

        // Rejecting a `base_ref` by character class is `core::policy`'s job (T24/T25). This module's
        // contract is narrower: `--end-of-options` makes such a ref harmless, so git sees it as a
        // revision and simply fails to resolve it — no flag injection, no panic, no pre-validation.
        let err = git::resolve_ref(repo.path(), "-weird")
            .await
            .expect_err("must not resolve");
        assert!(
            matches!(err, GitError::Failed { .. }),
            "git answered, not a local rejection: {err:?}"
        );
        let message = err.to_string();
        assert!(
            !message.contains("unknown option") && !message.contains("unknown switch"),
            "the ref was never parsed as a flag: {message}"
        );

        // A ref that resolves still resolves, and the result is a validated 40-hex sha.
        let sha = git::resolve_ref(repo.path(), "HEAD")
            .await
            .expect("resolve HEAD");
        assert_eq!(sha.len(), 40);
        assert!(sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    });
}

#[test]
fn a_git_planted_in_the_worktree_is_never_executed() {
    // Exclusive: rewrites the process-global PATH, like the timeout test.
    with_shimmed_git(|| async {
        let repo = init_repo();
        let real_sha = run_git(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        // The attack: an empty PATH entry means "the current directory" to execvp, and the current
        // directory of every git call is a worker-writable worktree.
        let marker = repo.path().join("PWNED");
        let planted = repo.path().join("git");
        fs::write(
            &planted,
            format!(
                "#!/bin/sh\ntouch {}\necho 0000000000000000000000000000000000000000\n",
                marker.display()
            ),
        )
        .expect("write planted git");
        fs::set_permissions(&planted, fs::Permissions::from_mode(0o755)).expect("chmod");

        let original_path = std::env::var("PATH").expect("PATH");
        std::env::set_var("PATH", ":/usr/bin:/bin");
        let result = git::head_sha(repo.path()).await;
        std::env::set_var("PATH", original_path);

        // The marker is the direct evidence of code execution; check it first so a regression says
        // exactly what happened. (Pre-fix this fires: the planted script runs and its output is
        // mixed into the daemon's view of `rev-parse`.)
        assert!(
            !marker.exists(),
            "the planted ./git must never be executed by the daemon"
        );
        assert_eq!(
            result.expect("the real git answers"),
            real_sha,
            "the real git ran, not the planted one"
        );
    });
}

#[test]
fn a_hung_git_fails_with_timeout_at_the_overridden_limit() {
    with_shimmed_git(|| async {
        let bin_dir = tempfile::tempdir().expect("tempdir");
        let shim = bin_dir.path().join("git");
        fs::write(&shim, "#!/bin/sh\nsleep 5\n").expect("write shim");
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("chmod");

        let repo_dir = tempfile::tempdir().expect("tempdir");
        let original_path = std::env::var("PATH").expect("PATH");
        std::env::set_var(
            "PATH",
            format!("{}:{original_path}", bin_dir.path().display()),
        );
        // Test-only override of GIT_OP_TIMEOUT, honoured only in debug builds — see git_op_timeout().
        std::env::set_var("ACP_TEST_GIT_TIMEOUT_MS", "1000");

        let started = Instant::now();
        let result = git::head_sha(repo_dir.path()).await;
        let elapsed = started.elapsed();

        std::env::set_var("PATH", original_path);
        std::env::remove_var("ACP_TEST_GIT_TIMEOUT_MS");

        let err = result.expect_err("the shim never answers");
        assert!(
            matches!(
                err,
                GitError::Timeout {
                    op: "head_sha",
                    secs: 1
                }
            ),
            "expected a 1s timeout, got {err:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "the timeout waited for its limit: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the child was killed at the limit, not left to sleep 5s: {elapsed:?}"
        );
    });
}

// ---------------------------------------------------------------------------
// Pathspec magic (Codex review of T35, round 2, finding 2)
// ---------------------------------------------------------------------------

/// A reviewed path is a **path**, never a pattern — and a path that *looks* like a pattern stops
/// the approval rather than being staged.
///
/// `git add -- ':(glob)*'` matches everything, and `--` does not turn that off. Two independent
/// things prevent it: `stage_paths` refuses a `:`-prefixed path outright (asserted here), and
/// `GIT_LITERAL_PATHSPECS=1` disables the syntax for every git call this module makes (asserted in
/// the next test, which reaches git through a path the check never sees). Refusing is the right
/// answer for an approval: a worktree holding a file called `:(glob)*` is a probe, and the run
/// should stop for a human rather than integrate.
#[test]
fn a_filename_that_looks_like_pathspec_magic_stops_the_approval() {
    with_real_git(|| async {
        let repo = init_repo();
        // The bait: a file whose name is a glob pathspec, and a bystander it would have matched.
        let literal = ":(glob)*";
        fs::write(repo.path().join(literal), "the reviewed one\n").expect("write the bait");
        fs::write(repo.path().join("bystander.txt"), "never reviewed\n").expect("write");

        let err = git::stage_paths(repo.path(), &[literal.to_string()])
            .await
            .expect_err("a path that looks like magic is refused");
        assert!(
            matches!(&err, GitError::InvalidRef { op, value } if *op == "stage_paths" && value == literal),
            "{err:?}"
        );
        assert!(
            run_git(repo.path(), &["diff", "--cached", "--name-only"])
                .trim()
                .is_empty(),
            "nothing at all was staged"
        );
    });
}

/// `GIT_LITERAL_PATHSPECS` is doing its own job, independently of the path check.
///
/// This reaches git through a pathspec the check never sees: the paths `frozen_diff_cached` passes
/// come out of the **index**, so a file staged by somebody else — a human, a script — arrives with
/// whatever name it has. With magic on, `git ls-files -- ':(glob)*'` would list every staged file
/// and the section rendered for it would carry another file's contents; with the variable set it
/// lists exactly one.
#[test]
fn literal_pathspecs_keep_a_magic_filename_from_matching_its_neighbours() {
    with_real_git(|| async {
        let repo = init_repo();
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::write(repo.path().join(":(glob)*"), "the file that is named like magic\n")
            .expect("write the bait");
        // Sorts *before* `:` (0x30 < 0x3A), so with the magic on it is the first entry
        // `git ls-files -- ':(glob)*'` would return — and the section below would carry its bytes.
        fs::write(repo.path().join("0-first.txt"), "a neighbour git would sort first\n")
            .expect("write");
        // Staged outside `stage_paths`, exactly as a human would.
        run_git(repo.path(), &["add", "-A"]);

        let out = repo.path().join("staged.patch");
        let stat = git::frozen_diff_cached(repo.path(), &pre_sha, &out)
            .await
            .expect("freeze the index");
        assert_eq!(
            stat.files,
            vec!["0-first.txt".to_string(), ":(glob)*".to_string()]
        );

        let text = fs::read_to_string(&out).expect("the staged diff");
        assert!(
            text.contains("+the file that is named like magic"),
            "the magic-named file must carry its own contents: {text}"
        );
        assert_eq!(
            text.matches("+a neighbour git would sort first").count(),
            1,
            "its neighbour must appear exactly once, under its own name: {text}"
        );
    });
}

/// The same rule stated as a refusal: a path that *begins* with `:` never reaches an argv at all.
///
/// Belt to `GIT_LITERAL_PATHSPECS`'s braces — a future call made without that environment still
/// cannot be handed magic, because the check runs first.
#[test]
fn pathspec_magic_and_traversal_are_refused_before_git_sees_them() {
    with_real_git(|| async {
        let repo = init_repo();
        fs::write(repo.path().join("real.txt"), "work\n").expect("write");

        for bad in [
            ":(glob)*",
            ":/",
            ":(top)x",
            ":(exclude)real.txt",
            "../escape.txt",
            "/etc/passwd",
            "-rf",
            "",
        ] {
            let err = git::stage_paths(repo.path(), &[bad.to_string()])
                .await
                .expect_err("`{bad}` must be refused");
            assert!(
                matches!(&err, GitError::InvalidRef { op, value } if *op == "stage_paths" && value == bad),
                "`{bad}` was refused as {err:?}"
            );
        }

        assert!(
            run_git(repo.path(), &["diff", "--cached", "--name-only"])
                .trim()
                .is_empty(),
            "a refused path stages nothing"
        );
    });
}

/// An empty path set is a refusal too: `git commit` with an empty index is not "commit everything".
#[test]
fn staging_nothing_is_refused_rather_than_staging_everything() {
    with_real_git(|| async {
        let repo = init_repo();
        fs::write(repo.path().join("real.txt"), "work\n").expect("write");

        let err = git::stage_paths(repo.path(), &[])
            .await
            .expect_err("an empty set is not a change set");
        assert!(matches!(&err, GitError::InvalidRef { op, .. } if *op == "stage_paths"));
        assert!(run_git(repo.path(), &["diff", "--cached", "--name-only"])
            .trim()
            .is_empty());
    });
}

/// `assert_index_clean` is the approval's precondition: it passes on a clean index and refuses on a
/// dirty one, naming itself so the run's block reason says which check stopped it.
#[test]
fn a_dirty_index_is_refused_and_a_clean_one_is_not() {
    with_real_git(|| async {
        let repo = init_repo();
        git::assert_index_clean(repo.path())
            .await
            .expect("a fresh repository has a clean index");

        fs::write(repo.path().join("staged.txt"), "work\n").expect("write");
        run_git(repo.path(), &["add", "--", "staged.txt"]);

        let err = git::assert_index_clean(repo.path())
            .await
            .expect_err("a dirty index is refused");
        assert!(
            matches!(&err, GitError::Failed { op, .. } if *op == "verify_index"),
            "{err:?}"
        );

        git::unstage_paths(repo.path(), &["staged.txt".to_string()])
            .await
            .expect("unstage");
        git::assert_index_clean(repo.path())
            .await
            .expect("unstaging restores the precondition");
    });
}

/// The staged freeze reproduces the worktree freeze byte for byte.
///
/// This is the equality the whole approval path rests on: the reviewer is shown `frozen_diff` of the
/// worktree, and the commit is authorised by `frozen_diff_cached` of the index. If the two ever
/// drift — a renderer changed on one side, a rename collapsed on the other — every integration
/// would either be refused or, worse, authorised against a different document.
#[test]
fn the_staged_freeze_reproduces_the_worktree_freeze() {
    with_real_git(|| async {
        let repo = init_repo();
        // One tracked file to modify, one to delete, plus untracked additions of every shape the
        // renderer distinguishes: text, no trailing newline, binary, and a symlink.
        fs::write(repo.path().join("tracked.txt"), "before\n").expect("write");
        fs::write(repo.path().join("doomed.txt"), "goes away\n").expect("write");
        run_git(repo.path(), &["add", "-A"]);
        run_git(repo.path(), &["commit", "--quiet", "-m", "base"]);
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::write(repo.path().join("tracked.txt"), "after\n").expect("write");
        fs::remove_file(repo.path().join("doomed.txt")).expect("remove");
        fs::create_dir_all(repo.path().join("src")).expect("mkdir");
        fs::write(repo.path().join("src/new.ts"), "export const add = 1;\n").expect("write");
        fs::write(repo.path().join("src/tail.ts"), "no newline").expect("write");
        fs::write(repo.path().join("src/blob.bin"), [0u8, 1, 2, 3]).expect("write");
        std::os::unix::fs::symlink("/etc/passwd", repo.path().join("src/link")).expect("symlink");

        let reviewed = repo.path().join("reviewed.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        assert!(
            from_worktree.symlinks.contains(&"src/link".to_string()),
            "the symlink is named, never followed: {:?}",
            from_worktree.symlinks
        );

        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage the reviewed set");

        let staged_path = repo.path().join("staged.patch");
        let from_index = git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path)
            .await
            .expect("freeze the index");

        assert_eq!(from_index.files, from_worktree.files);
        assert_eq!(from_index.symlinks, from_worktree.symlinks);
        assert_eq!(
            fs::read_to_string(&staged_path).expect("staged"),
            fs::read_to_string(&reviewed).expect("reviewed"),
            "the two freezes must be the same document"
        );
        assert_eq!(
            git::sha256_file(&staged_path).await,
            git::sha256_file(&reviewed).await,
        );
    });
}

/// A tracked modification much larger than the assembled budget is bounded identically on both
/// sides of the approval boundary.
#[test]
fn a_twenty_megabyte_tracked_modification_has_one_bounded_freeze() {
    with_real_git(|| async {
        let repo = init_repo();
        fs::write(repo.path().join("tracked.txt"), "before\n").expect("write base");
        run_git(repo.path(), &["add", "--", "tracked.txt"]);
        run_git(repo.path(), &["commit", "--quiet", "-m", "base"]);
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        fs::write(repo.path().join("tracked.txt"), large_tracked_contents())
            .expect("write 20 MiB modification");

        let reviewed = repo.path().join("reviewed-large.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        let reviewed_bytes = fs::read(&reviewed).expect("read reviewed patch");
        assert!(
            reviewed_bytes.ends_with(FROZEN_DIFF_TRUNCATION_MARKER),
            "the global cap has to have bitten"
        );
        assert!(
            reviewed_bytes.len() <= MAX_FROZEN_DIFF_BYTES + FROZEN_DIFF_TRUNCATION_MARKER.len(),
            "bounded artifact is {} bytes",
            reviewed_bytes.len()
        );
        assert!(
            reviewed_bytes.len() > MAX_FROZEN_DIFF_BYTES - 1024,
            "fixed-width lines should exercise the boundary, not an accidental small prefix"
        );
        assert_eq!(
            git::sha256_file(&reviewed).await.as_deref(),
            Some(from_worktree.diff_hash.as_str()),
            "the write-time digest covers the exact file"
        );

        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage reviewed path");
        let staged_path = repo.path().join("staged-large.patch");
        let from_index = git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path)
            .await
            .expect("freeze the index");
        let staged_bytes = fs::read(&staged_path).expect("read staged patch");

        assert_eq!(staged_bytes, reviewed_bytes, "both freezes are byte-identical");
        assert_eq!(from_index.diff_hash, from_worktree.diff_hash);
        assert_eq!(from_index.files, from_worktree.files);
        assert_eq!(from_index.added, from_worktree.added);
        assert_eq!(from_index.deleted, from_worktree.deleted);
    });
}

/// Output beyond the cap is still drained and the command's final failure is authoritative.
///
/// A prefix-only implementation that killed git at the cap would incorrectly accept this output as
/// a frozen diff and never observe the deliberately late non-zero exit.
#[test]
fn a_git_diff_that_fails_after_the_cap_is_rejected() {
    with_shimmed_git(|| async {
        let repo = init_repo();
        fs::write(repo.path().join("tracked.txt"), "before\n").expect("write base");
        run_git(repo.path(), &["add", "--", "tracked.txt"]);
        run_git(repo.path(), &["commit", "--quiet", "-m", "base"]);
        fs::write(repo.path().join("tracked.txt"), large_tracked_contents())
            .expect("write 20 MiB modification");

        let real_git = {
            let out = Command::new("/bin/sh")
                .args(["-c", "command -v git"])
                .output()
                .expect("locate git");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let bin_dir = tempfile::tempdir().expect("tempdir");
        let shim = bin_dir.path().join("git");
        fs::write(
            &shim,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = diff ]; then\n\
                   \"{real_git}\" \"$@\"\n\
                   printf 'late diff failure\\n' >&2\n\
                   exit 1\n\
                 fi\n\
                 exec \"{real_git}\" \"$@\"\n"
            ),
        )
        .expect("write shim");
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("chmod");

        let original_path = std::env::var("PATH").expect("PATH");
        std::env::set_var(
            "PATH",
            format!("{}:{original_path}", bin_dir.path().display()),
        );
        let out = repo.path().join("must-not-be-trusted.patch");
        let frozen = git::frozen_diff(repo.path(), &out).await;
        std::env::set_var("PATH", original_path);

        let err = frozen.expect_err("a late git failure must invalidate its stdout prefix");
        let GitError::Failed {
            op,
            status: _,
            message,
        } = err
        else {
            panic!("expected a git failure, got {err:?}");
        };
        assert_eq!(op, "frozen_diff");
        assert!(message.contains("late diff failure"), "{message}");
        assert!(
            !out.exists(),
            "failed git output must never be written as a trusted artifact"
        );
    });
}

// ---------------------------------------------------------------------------
// Normalization (round-3 review, finding 2)
// ---------------------------------------------------------------------------

/// `.gitattributes` rewrites the bytes on the way into the repository; both freezes must show the
/// rewritten ones.
///
/// A reviewer is shown the diff of an untracked file read from disk, and an approval re-derives that
/// diff from the index. With `* text` and a CRLF file the index holds LF and the disk holds CRLF, so
/// a freeze that reported the raw bytes could never be reproduced at approval time: every such run
/// would be refused with "worktree changed since review" when nothing had changed at all.
#[test]
fn a_crlf_file_under_text_attributes_freezes_the_same_from_disk_and_from_the_index() {
    with_real_git(|| async {
        let repo = init_repo();
        fs::write(repo.path().join(".gitattributes"), "*.txt text\n").expect("write attributes");
        run_git(repo.path(), &["add", "-A"]);
        run_git(repo.path(), &["commit", "--quiet", "-m", "attributes"]);
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::write(repo.path().join("windows.txt"), "one\r\ntwo\r\n").expect("write CRLF");

        let reviewed = repo.path().join("reviewed.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        let text = fs::read_to_string(&reviewed).expect("reviewed");
        assert!(
            !text.contains('\r'),
            "the reviewer is shown what git would store, not the carriage returns: {text:?}"
        );

        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage");
        let staged_path = repo.path().join("staged.patch");
        git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path)
            .await
            .expect("freeze the index");

        assert_eq!(
            fs::read_to_string(&staged_path).expect("staged"),
            text,
            "the two freezes must agree once git's own normalization is applied"
        );
    });
}

/// The same for a `filter.*.clean` driver — git-lfs is the one everybody has, and it rewrites the
/// file into a pointer on the way in.
#[test]
fn a_clean_filter_freezes_the_same_from_disk_and_from_the_index() {
    with_real_git(|| async {
        let repo = init_repo();
        // A clean filter that is obviously not the identity, and needs no external tooling.
        run_git(repo.path(), &["config", "filter.shout.clean", "tr a-z A-Z"]);
        fs::write(repo.path().join(".gitattributes"), "*.ptr filter=shout\n")
            .expect("write attributes");
        run_git(repo.path(), &["add", "-A"]);
        run_git(repo.path(), &["commit", "--quiet", "-m", "attributes"]);
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::write(repo.path().join("payload.ptr"), "quiet content\n").expect("write");

        let reviewed = repo.path().join("reviewed.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        let text = fs::read_to_string(&reviewed).expect("reviewed");
        assert!(
            text.contains("+QUIET CONTENT"),
            "the reviewer sees the filtered bytes — what would actually be committed: {text}"
        );

        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage");
        let staged_path = repo.path().join("staged.patch");
        git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path)
            .await
            .expect("freeze the index");

        assert_eq!(
            fs::read_to_string(&staged_path).expect("staged"),
            text,
            "a clean filter must not make the two freezes disagree"
        );
        assert_eq!(
            git::sha256_file(&staged_path).await,
            git::sha256_file(&reviewed).await
        );
    });
}

// ---------------------------------------------------------------------------
// The inline cap (round-4 review, findings 1 and 3)
// ---------------------------------------------------------------------------

/// `MAX_UNTRACKED_DIFF_BYTES`, which the module keeps private. Named here so the arithmetic below
/// reads as "one line either side of the cap" rather than as a magic number.
const INLINE_CAP: usize = 256 * 1024;

/// A 70-byte line, so the cap at 256 KiB lands in the **middle** of one: 3744 whole lines is
/// 262 080 bytes and the 3745th spans the boundary. That is exactly where two capping rules can
/// part company, and where a flat truncate and a cut-back-to-the-last-newline give different bytes.
fn long_line() -> String {
    let line = format!("export const value = 0; // {}\n", "x".repeat(42));
    assert_eq!(line.len(), 70, "the arithmetic above depends on this");
    line
}

/// A 300-byte record with a NUL in it (so the renderer calls the file binary) and a newline at the
/// end (so the newline trim has something to find). 873 records is 261 900 bytes; the cap at
/// 262 144 falls inside the 874th.
fn binary_record() -> Vec<u8> {
    let mut record = vec![b'a'; 299];
    record[100] = 0;
    record.push(b'\n');
    record
}

/// A new text file past the inline cap freezes the same from disk and from the index.
///
/// The two sources capped it by different rules — the worktree read cut back to the last newline,
/// the index read truncated flat — so the freeze and the re-freeze differed by the length of one
/// line for **every** large new file. The approval refused with "worktree changed since review" and
/// the discriminator then blamed `.gitattributes` for a repository that has none (round-4 review,
/// finding 1). Nothing about this file is exotic: no attributes, no filter, just size.
#[test]
fn a_new_text_file_past_the_cap_freezes_the_same_from_disk_and_from_the_index() {
    with_real_git(|| async {
        let repo = init_repo();
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::create_dir_all(repo.path().join("src")).expect("mkdir");
        fs::write(repo.path().join("src/huge.ts"), long_line().repeat(4_500)).expect("write");

        let reviewed = repo.path().join("reviewed.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        let text = fs::read_to_string(&reviewed).expect("reviewed");
        assert!(
            text.contains("(untracked file truncated by the control plane)"),
            "the cap has to have bitten, or this test proves nothing"
        );

        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage");
        let staged_path = repo.path().join("staged.patch");
        git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path)
            .await
            .expect("freeze the index");

        assert_eq!(
            fs::read_to_string(&staged_path).expect("staged"),
            text,
            "a file past the cap must cap to the same bytes from either side"
        );
        assert_eq!(
            git::sha256_file(&staged_path).await,
            git::sha256_file(&reviewed).await
        );
    });
}

/// The same for a binary file past the cap, where the disagreement was visible in the byte count
/// the section reports: 262 055 from the worktree against 262 144 from the index.
#[test]
fn a_new_binary_file_past_the_cap_freezes_the_same_from_disk_and_from_the_index() {
    with_real_git(|| async {
        let repo = init_repo();
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::create_dir_all(repo.path().join("src")).expect("mkdir");
        fs::write(repo.path().join("src/huge.bin"), binary_record().repeat(1_000)).expect("write");

        let reviewed = repo.path().join("reviewed.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        let text = fs::read_to_string(&reviewed).expect("reviewed");
        // 873 whole 300-byte records: the cap cut inside the 874th and the trim went back to the
        // last newline before it. Both sides have to report *this* count.
        assert!(
            text.contains("(261900 bytes)"),
            "the binary section must report the capped-and-trimmed length: {text}"
        );

        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage");
        let staged_path = repo.path().join("staged.patch");
        git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path)
            .await
            .expect("freeze the index");

        assert_eq!(
            fs::read_to_string(&staged_path).expect("staged"),
            text,
            "a binary file past the cap must cap to the same bytes from either side"
        );
    });
}

/// The index side never reads a blob whole: it asks how big it is first.
///
/// `index_section` used to `git cat-file blob` an entire object into a `Vec` and truncate it
/// afterwards, which made a worker's file a worker's choice of how much of the privileged daemon's
/// memory to spend (round-4 review, finding 3). A test cannot watch an allocation, so this watches
/// the mechanism that bounds it: every git invocation is logged by a shim, and the daemon has to ask
/// `cat-file -s` for the size **before** it reads any content — that answer is what sends an
/// over-cap blob down the bounded-prefix route instead of the drain-it-all one. The rendered section
/// is asserted too, so the bound is pinned at both ends.
#[test]
fn a_multi_megabyte_new_file_has_its_size_probed_before_it_is_read() {
    // Exclusive: rewrites the process-global PATH, like the other shim tests.
    with_shimmed_git(|| async {
        let repo = init_repo();
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::create_dir_all(repo.path().join("src")).expect("mkdir");
        let content = long_line().repeat(45_000);
        assert!(content.len() > 3_000_000, "the file has to dwarf the cap");
        fs::write(repo.path().join("src/enormous.ts"), &content).expect("write");

        let reviewed = repo.path().join("reviewed.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage");
        // The object the approval will read back, named before the shim is in the way.
        let blob = run_git(repo.path(), &["ls-files", "--stage", "--", "src/enormous.ts"])
            .split_whitespace()
            .nth(1)
            .expect("a staged blob sha")
            .to_string();

        // A shim that records every argv and hands the call to the real git.
        let real_git = {
            let out = Command::new("/bin/sh")
                .args(["-c", "command -v git"])
                .output()
                .expect("locate git");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let bin_dir = tempfile::tempdir().expect("tempdir");
        let log = bin_dir.path().join("argv.log");
        let shim = bin_dir.path().join("git");
        fs::write(
            &shim,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexec {real_git} \"$@\"\n",
                log.display()
            ),
        )
        .expect("write shim");
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("chmod");

        let original_path = std::env::var("PATH").expect("PATH");
        std::env::set_var(
            "PATH",
            format!("{}:{original_path}", bin_dir.path().display()),
        );
        let staged_path = repo.path().join("staged.patch");
        let frozen = git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path).await;
        std::env::set_var("PATH", original_path);
        frozen.expect("freeze the index");

        let calls: Vec<String> = fs::read_to_string(&log)
            .expect("the shim logged something")
            .lines()
            .map(str::to_string)
            .collect();
        let sized = calls
            .iter()
            .position(|call| *call == format!("cat-file -s {blob}"))
            .unwrap_or_else(|| panic!("the blob's size is never asked for: {calls:?}"));
        let read = calls
            .iter()
            .position(|call| *call == format!("cat-file blob {blob}"));
        assert!(
            read.is_none_or(|read| read > sized),
            "the size has to be known before any content is read: {calls:?}"
        );

        let staged = fs::read_to_string(&staged_path).expect("staged");
        // The `+` prefix on every line and the section headers are the only slack over the cap.
        assert!(
            staged.len() < INLINE_CAP + 8 * 1024,
            "the index section is bounded by the cap, not by the file: {} bytes",
            staged.len()
        );
        assert_eq!(
            staged,
            fs::read_to_string(&reviewed).expect("reviewed"),
            "and it is still the document the reviewer was shown"
        );
    });
}

/// A git failure that is not "the index is dirty" is reported as itself.
///
/// `git diff --cached --quiet` exits **1** for "there are differences" and 128 for a fault. Folding
/// every non-zero exit into "the index already holds staged changes" sent a human to `git reset` for
/// a corrupt index that no reset would fix (round-4 review, finding 5).
#[test]
fn a_broken_index_check_is_not_reported_as_a_dirty_index() {
    with_real_git(|| async {
        let repo = init_repo();
        fs::write(repo.path().join(".git/index"), b"garbage").expect("corrupt the index");

        let err = git::assert_index_clean(repo.path())
            .await
            .expect_err("a corrupt index is a failure");
        let GitError::Failed {
            op,
            status,
            message,
        } = &err
        else {
            panic!("expected a failure, got {err:?}");
        };
        assert_eq!(*op, "verify_index");
        assert!(
            !message.contains("already holds staged changes"),
            "a fault must not be reported as a dirty index: {message}"
        );
        assert!(message.contains("index file"), "{message}");
        assert!(status.contains("128"), "{status}");
    });
}

// ---------------------------------------------------------------------------
// File modes (round-4 review, finding 2)
// ---------------------------------------------------------------------------

/// A new **executable** file is reviewed as executable, and re-derived the same way from the index.
///
/// The renderer hard-coded `new file mode 100644` on both sides while the index side read — and
/// threw away — the mode git had actually recorded. So a worker adding a build script got it
/// reviewed as an ordinary file: the human approving it could not see that the change installs
/// something runnable, which is the whole point of the mode being in a diff at all. (The two sides
/// agreed only because both were wrong in the same way; reading the mode on one side alone would
/// have turned this into a refusal instead.)
#[test]
fn a_new_executable_file_freezes_the_same_from_disk_and_from_the_index() {
    with_real_git(|| async {
        let repo = init_repo();
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::create_dir_all(repo.path().join("src")).expect("mkdir");
        // One of each, so the test says "the mode is read" rather than "the constant changed".
        fs::write(repo.path().join("src/run.sh"), "#!/bin/sh\necho hi\n").expect("write");
        fs::set_permissions(
            repo.path().join("src/run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("chmod");
        fs::write(repo.path().join("src/plain.ts"), "export const add = 1;\n").expect("write");

        let reviewed = repo.path().join("reviewed.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        let text = fs::read_to_string(&reviewed).expect("reviewed");
        assert!(
            text.contains("diff --git a/src/run.sh b/src/run.sh\nnew file mode 100755\n"),
            "the reviewer has to be shown that the new file is executable: {text}"
        );
        assert!(
            text.contains("diff --git a/src/plain.ts b/src/plain.ts\nnew file mode 100644\n"),
            "and that the other one is not: {text}"
        );

        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage");
        // What git itself recorded, so the assertion above is anchored to git's answer.
        assert!(
            run_git(repo.path(), &["ls-files", "--stage", "--", "src/run.sh"])
                .starts_with("100755"),
            "the fixture must really be executable in the index"
        );

        let staged_path = repo.path().join("staged.patch");
        git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path)
            .await
            .expect("freeze the index");
        assert_eq!(
            fs::read_to_string(&staged_path).expect("staged"),
            text,
            "both freezes must render the same mode for the same file"
        );
        assert_eq!(
            git::sha256_file(&staged_path).await,
            git::sha256_file(&reviewed).await
        );
    });
}

/// A repository that does not honour the executable bit renders 100644 on **both** sides.
///
/// `core.fileMode=false` is what a repo on a mounted volume (or one cloned on Windows) looks like:
/// git stores 100644 whatever the filesystem says. A freeze that read `st_mode` and stopped there
/// would render 100755, the approval would re-derive 100644 from the index, and the run could never
/// integrate — the failure this round exists to remove, reintroduced by the fix for it.
#[test]
fn a_repository_that_ignores_the_exec_bit_renders_one_mode_on_both_sides() {
    with_real_git(|| async {
        let repo = init_repo();
        run_git(repo.path(), &["config", "core.fileMode", "false"]);
        let pre_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).trim().to_string();

        fs::create_dir_all(repo.path().join("src")).expect("mkdir");
        fs::write(repo.path().join("src/run.sh"), "#!/bin/sh\necho hi\n").expect("write");
        fs::set_permissions(
            repo.path().join("src/run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("chmod");

        let reviewed = repo.path().join("reviewed.patch");
        let from_worktree = git::frozen_diff(repo.path(), &reviewed)
            .await
            .expect("freeze the worktree");
        let text = fs::read_to_string(&reviewed).expect("reviewed");
        assert!(
            text.contains("new file mode 100644"),
            "git will store 100644 here, so that is what the reviewer must be shown: {text}"
        );

        git::stage_paths(repo.path(), &from_worktree.files)
            .await
            .expect("stage");
        let staged_path = repo.path().join("staged.patch");
        git::frozen_diff_cached(repo.path(), &pre_sha, &staged_path)
            .await
            .expect("freeze the index");
        assert_eq!(
            fs::read_to_string(&staged_path).expect("staged"),
            text,
            "core.fileMode must not make the two freezes disagree"
        );
    });
}
