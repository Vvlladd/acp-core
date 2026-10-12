//! Real Git, isolated repositories, no providers. Pins no-builder snapshot and mutation rules.
use agent_control_plane::workspace::git::{
    self,
    audit::{self, Selection, Target},
};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
fn repo() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "main"]);
    git(dir.path(), &["config", "user.name", "acp-test"]);
    git(
        dir.path(),
        &["config", "user.email", "acp-test@example.invalid"],
    );
    std::fs::write(dir.path().join("source.txt"), "original\n").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "initial"]);
    dir
}
async fn capture(repo: &Path, state: &Path, target: Target) -> audit::Snapshot {
    audit::capture(
        repo,
        Selection {
            base_ref: "HEAD".into(),
            target,
        },
        &state.join("artifacts"),
        &state.join("snapshot"),
        "acp-audit/test",
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn working_capture_preserves_partial_staging_and_later_source_edits() {
    let repo = repo();
    let state = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("source.txt"), "staged\n").unwrap();
    git(repo.path(), &["add", "source.txt"]);
    std::fs::write(repo.path().join("source.txt"), "unstaged\n").unwrap();
    std::fs::write(repo.path().join("new file.txt"), "untracked\n").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", repo.path().join("link")).unwrap();
    let index = std::fs::read(repo.path().join(".git/index")).unwrap();
    let head = git(repo.path(), &["rev-parse", "HEAD"]);
    let diff = git(repo.path(), &["diff", "--cached"]);
    let snapshot = capture(repo.path(), state.path(), Target::WorkingTree {}).await;
    assert_eq!(
        std::fs::read(repo.path().join(".git/index")).unwrap(),
        index
    );
    assert_eq!(git(repo.path(), &["rev-parse", "HEAD"]), head);
    assert_eq!(git(repo.path(), &["diff", "--cached"]), diff);
    assert_eq!(
        std::fs::read_to_string(snapshot.worktree.join("source.txt")).unwrap(),
        "unstaged\n"
    );
    assert_eq!(
        std::fs::read_to_string(snapshot.worktree.join("new file.txt")).unwrap(),
        "untracked\n"
    );
    assert_eq!(
        std::fs::read_link(snapshot.worktree.join("link")).unwrap(),
        Path::new("/etc/passwd")
    );
    let frozen = std::fs::read(&snapshot.diff_path).unwrap();
    assert!(String::from_utf8_lossy(&frozen).contains("+/etc/passwd"));
    std::fs::write(repo.path().join("source.txt"), "newer edit\n").unwrap();
    audit::validate(&snapshot).await.unwrap();
    assert_eq!(std::fs::read(&snapshot.diff_path).unwrap(), frozen);
    let decoded: audit::Snapshot =
        serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
    audit::validate(&decoded).await.unwrap();
}

#[tokio::test]
async fn build_outputs_are_allowed_but_index_hints_cannot_hide_source_mutation() {
    let repo = repo();
    let state = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("source.txt"), "selected\n").unwrap();
    let snapshot = capture(repo.path(), state.path(), Target::WorkingTree {}).await;
    std::fs::write(snapshot.worktree.join("build.log"), "output\n").unwrap();
    audit::validate(&snapshot).await.unwrap();
    git(
        &snapshot.worktree,
        &["update-index", "--assume-unchanged", "source.txt"],
    );
    std::fs::write(snapshot.worktree.join("source.txt"), "tampered\n").unwrap();
    assert!(audit::validate(&snapshot)
        .await
        .unwrap_err()
        .to_string()
        .contains("tracked source"));
    git(
        &snapshot.worktree,
        &["update-index", "--no-assume-unchanged", "source.txt"],
    );
    git(
        &snapshot.worktree,
        &["update-index", "--skip-worktree", "source.txt"],
    );
    assert!(audit::validate(&snapshot).await.is_err());
}

#[tokio::test]
async fn selected_revision_is_fixed_and_empty_input_needs_no_worktree() {
    let repo = repo();
    let state = tempfile::tempdir().unwrap();
    let empty = capture(
        repo.path(),
        state.path(),
        Target::Revision {
            revision: "HEAD".into(),
        },
    )
    .await;
    assert!(empty.files.is_empty());
    assert!(!empty.worktree.exists());
    audit::validate(&empty).await.unwrap();
    std::fs::write(repo.path().join("source.txt"), "committed change\n").unwrap();
    git(repo.path(), &["commit", "-qam", "change"]);
    let next = tempfile::tempdir().unwrap();
    let snapshot = audit::capture(
        repo.path(),
        Selection {
            base_ref: "HEAD~1".into(),
            target: Target::Revision {
                revision: "HEAD".into(),
            },
        },
        &next.path().join("artifacts"),
        &next.path().join("snapshot"),
        "acp-audit/revision",
    )
    .await
    .unwrap();
    std::fs::write(repo.path().join("source.txt"), "uncommitted later\n").unwrap();
    assert_eq!(
        std::fs::read_to_string(snapshot.worktree.join("source.txt")).unwrap(),
        "committed change\n"
    );
    audit::validate(&snapshot).await.unwrap();
    std::fs::write(&snapshot.diff_path, "forged diff").unwrap();
    assert!(audit::validate(&snapshot)
        .await
        .unwrap_err()
        .to_string()
        .contains("frozen audit diff"));
}

#[tokio::test]
async fn oversized_diff_and_invalid_base_refuse_without_touching_source_index() {
    let repo = repo();
    let state = tempfile::tempdir().unwrap();
    // Long textual lines produce a diff beyond the assembled budget without a large file list.
    std::fs::write(
        repo.path().join("large.txt"),
        vec![b'x'; git::MAX_FROZEN_DIFF_BYTES + 1024],
    )
    .unwrap();
    let index = std::fs::read(repo.path().join(".git/index")).unwrap();
    for base in ["HEAD", "--not-an-option"] {
        let result = audit::capture(
            repo.path(),
            Selection {
                base_ref: base.into(),
                target: Target::WorkingTree {},
            },
            &state.path().join("artifacts"),
            &state.path().join("snapshot"),
            "acp-audit/refused",
        )
        .await;
        assert!(result.is_err());
        assert!(!state.path().join("snapshot").exists());
        assert_eq!(
            std::fs::read(repo.path().join(".git/index")).unwrap(),
            index
        );
    }
}

#[tokio::test]
async fn clean_filters_and_filemode_settings_cannot_hide_raw_snapshot_changes() {
    let repo = repo();
    let state = tempfile::tempdir().unwrap();
    git(repo.path(), &["config", "filter.shout.clean", "tr a-z A-Z"]);
    git(repo.path(), &["config", "core.filemode", "false"]);
    std::fs::write(
        repo.path().join(".gitattributes"),
        "source.txt filter=shout\n",
    )
    .unwrap();
    git(repo.path(), &["add", ".gitattributes"]);
    git(repo.path(), &["commit", "-qm", "attributes"]);
    std::fs::write(repo.path().join("source.txt"), "selected bytes\n").unwrap();
    let snapshot = capture(repo.path(), state.path(), Target::WorkingTree {}).await;
    let path = snapshot.worktree.join("source.txt");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes, b"SELECTED BYTES\n");
    std::fs::write(&path, b"selected bytes\n").unwrap();
    assert!(audit::validate(&snapshot)
        .await
        .unwrap_err()
        .to_string()
        .contains("tracked source bytes"));
    std::fs::write(&path, &bytes).unwrap();
    audit::validate(&snapshot).await.unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
    assert!(audit::validate(&snapshot).await.is_err());
}

#[tokio::test]
async fn dirty_submodule_is_refused_instead_of_reported_as_empty_input() {
    let repo = repo();
    let nested = self::repo();
    let state = tempfile::tempdir().unwrap();
    git(
        repo.path(),
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            nested.path().to_str().unwrap(),
            "nested",
        ],
    );
    git(repo.path(), &["commit", "-qam", "submodule"]);
    std::fs::write(
        repo.path().join("nested/source.txt"),
        "uncommitted nested change\n",
    )
    .unwrap();
    let index = std::fs::read(repo.path().join(".git/index")).unwrap();
    let error = audit::capture(
        repo.path(),
        Selection {
            base_ref: "HEAD".into(),
            target: Target::WorkingTree {},
        },
        &state.path().join("artifacts"),
        &state.path().join("snapshot"),
        "acp-audit/nested",
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("submodules"));
    assert!(!state.path().join("snapshot").exists());
    assert_eq!(
        std::fs::read(repo.path().join(".git/index")).unwrap(),
        index
    );
}

#[tokio::test]
async fn exactly_one_byte_over_the_diff_budget_is_refused() {
    let repo = repo();
    let state = tempfile::tempdir().unwrap();
    let path = repo.path().join("boundary.txt");
    std::fs::write(&path, b"x").unwrap();
    git(repo.path(), &["add", "boundary.txt"]);
    let args = [
        "diff",
        "--cached",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--no-renames",
        "--binary",
        "HEAD",
        "--",
    ];
    let overhead = git(repo.path(), &args).len() - 1;
    std::fs::write(&path, vec![b'x'; git::MAX_FROZEN_DIFF_BYTES + 1 - overhead]).unwrap();
    git(repo.path(), &["add", "boundary.txt"]);
    assert_eq!(
        git(repo.path(), &args).len(),
        git::MAX_FROZEN_DIFF_BYTES + 1
    );
    let error = audit::capture(
        repo.path(),
        Selection {
            base_ref: "HEAD".into(),
            target: Target::WorkingTree {},
        },
        &state.path().join("artifacts"),
        &state.path().join("snapshot"),
        "acp-audit/boundary",
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("8 MiB"));
    assert!(!state.path().join("snapshot").exists());
}

#[tokio::test]
async fn unchanged_tracked_paths_stay_in_the_artifact_instead_of_the_socket_summary() {
    let repo = repo();
    let state = tempfile::tempdir().unwrap();
    for index in 0..3000 {
        let name = format!("{index:04}-{}.txt", "p".repeat(180));
        std::fs::write(repo.path().join(name), b"").unwrap();
    }
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-qm", "large path manifest"]);
    std::fs::write(repo.path().join("source.txt"), "one small changed file\n").unwrap();
    let snapshot = capture(repo.path(), state.path(), Target::WorkingTree {}).await;
    assert!(std::fs::metadata(&snapshot.manifest_path).unwrap().len() > 512 * 1024);
    assert!(serde_json::to_vec(&snapshot).unwrap().len() < 4096);
    assert_eq!(snapshot.files, ["source.txt"]);
    std::fs::write(&snapshot.manifest_path, b"[]").unwrap();
    assert!(audit::validate(&snapshot)
        .await
        .unwrap_err()
        .to_string()
        .contains("manifest changed"));
}
