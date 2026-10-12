//! Human navigation only. No socket mutation, daemon startup, session resume or gate action.
use super::*;

fn task_link(repo: &Path, run: uuid::Uuid) -> anyhow::Result<String> {
    let path = repo
        .to_str()
        .context("task links require a UTF-8 repository path")?;
    let mut encoded = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}")?;
        }
    }
    Ok(format!("acp-control-plane://task/{run}?repo={encoded}"))
}

pub(super) async fn open_task_app(
    repo: Option<&Path>,
    run: uuid::Uuid,
    print: bool,
) -> anyhow::Result<i32> {
    let root = git::repo_root(&cwd(repo)?).await?;
    let root = fs::canonicalize(root)?;
    let link = task_link(&root, run)?;
    if print {
        println!("{link}");
        return Ok(EXIT_OK);
    }
    #[cfg(target_os = "macos")]
    {
        // Fixed system tool and app bundle id. The URL is one argument, never shell source.
        let mut command = tokio::process::Command::new("/usr/bin/open");
        command
            .args(["-b", "dev.acp.acp-mac", &link])
            .kill_on_drop(true);
        let status = tokio::time::timeout(Duration::from_secs(10), command.status())
            .await
            .context("opening the app timed out")??;
        if !status.success() {
            bail!("ACP could not open its Mac app. Install the app or use --print to copy the task link.");
        }
        eprintln!(
            "Opened the task in ACP. Continue coordination in this original host conversation."
        );
        Ok(EXIT_OK)
    }
    #[cfg(not(target_os = "macos"))]
    {
        bail!("opening the app requires macOS; use --print to copy the task link")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_encodes_every_query_delimiter_and_unicode() {
        let run = uuid::Uuid::nil();
        let link = task_link(Path::new("/tmp/café & x?#%"), run).unwrap();
        assert_eq!(link, "acp-control-plane://task/00000000-0000-0000-0000-000000000000?repo=%2Ftmp%2Fcaf%C3%A9%20%26%20x%3F%23%25");
    }
    #[test]
    fn command_requires_a_run_uuid() {
        use clap::Parser as _;
        assert!(Cli::try_parse_from(["acp", "app", "not-a-run"]).is_err());
        assert!(
            Cli::try_parse_from(["acp", "app", &uuid::Uuid::nil().to_string(), "--print"]).is_ok()
        );
    }
}
