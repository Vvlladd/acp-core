//! Fixed, bundled analyzer launch. No project-controlled program, arguments or environment.
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const PROFILE: &str = "(version 1)(deny default)(allow process-exec (literal (param \"HELPER\")))(allow signal (target self))(allow sysctl-read)(allow file-read-metadata)(allow mach-lookup)(allow file-read* (literal \"/\") (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/Library/Apple\") (subpath \"/System/Volumes/Preboot/Cryptexes\") (subpath \"/private/preboot/Cryptexes\") (literal (param \"HELPER\")))(allow file-write* (literal \"/dev/null\"))";

/// A helper must be a regular executable installed next to the running ACP binary. Relative
/// PATH lookup, environment overrides and helpers in the repository are deliberately absent.
pub struct CheckedAnalyzer(PathBuf);
impl CheckedAnalyzer {
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

pub fn helper() -> Result<CheckedAnalyzer, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = executable
        .parent()
        .ok_or("ACP executable has no directory")?
        .join("acp-swift-checks");
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
        "Swift Review is not installed. Install the ACP package containing acp-swift-checks."
            .to_string()
    })?;
    use std::os::unix::fs::PermissionsExt;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("Swift Review analyzer is not a regular executable".into());
    }
    Ok(CheckedAnalyzer(
        path.canonicalize().map_err(|e| e.to_string())?,
    ))
}

pub async fn analyze(
    analyzer: &CheckedAnalyzer,
    input: Vec<u8>,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, String> {
    if !cfg!(target_os = "macos") {
        return Err("Swift Review requires macOS".into());
    }
    let checked = analyzer.path();
    let mut command = tokio::process::Command::new("/usr/bin/sandbox-exec");
    command.args([
        "-D",
        &format!("HELPER={}", checked.display()),
        "-p",
        PROFILE,
    ]);
    command
        .arg(checked)
        .env_clear()
        .env("LANG", "en_US.UTF-8")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // Even if the daemon dies, the source-only helper has a finite CPU budget.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 60,
                rlim_max: 60,
            };
            if libc::setrlimit(libc::RLIMIT_CPU, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Cannot start Swift Review: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("Missing analyzer input")?;
    let stdout = child.stdout.take().ok_or("Missing analyzer output")?;
    let work = async {
        let write = async move {
            stdin.write_all(&input).await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok::<_, std::io::Error>(())
        };
        let read = async {
            let mut bytes = Vec::new();
            stdout
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let (_, bytes) = tokio::try_join!(write, read).map_err(|e| e.to_string())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("Analyzer output exceeded its limit".into());
        }
        let status = child.wait().await.map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("Swift Review analyzer failed; no clean review is claimed".into());
        }
        Ok(bytes)
    };
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => Err("Review cancelled".into()),
        result = tokio::time::timeout(Duration::from_secs(60), work) => result.unwrap_or_else(|_| Err("Swift Review exceeded 60 seconds".into())),
    };
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}
