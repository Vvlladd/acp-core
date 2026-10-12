//! Host-process ownership. All OS inspection is bounded and runs outside the core actor.

use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
use tokio::{io::AsyncReadExt, process::Command};

use crate::core::lifecycle::OwnerProcess;

/// Fixed ps fields and one numeric pid only; no shell or caller-provided flags.
pub async fn process_fields(pid: i32, parent: bool) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    let fields = if parent {
        "ppid=,comm="
    } else {
        "stat=,lstart="
    };
    let mut child = Command::new("/bin/ps")
        .args(["-o", fields, "-p", &pid.to_string()])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?.take(8193);
    let mut bytes = Vec::new();
    let outcome = tokio::time::timeout(Duration::from_millis(500), async {
        stdout.read_to_end(&mut bytes).await.ok()?;
        let status = child.wait().await.ok()?;
        (status.success() && bytes.len() <= 8192).then_some(())
    })
    .await;
    if !matches!(outcome, Ok(Some(()))) {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_millis(500), child.wait()).await;
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn identity(fields: &str) -> Option<&str> {
    let (state, start) = fields.split_once(char::is_whitespace)?;
    if state.starts_with('Z') || start.trim().is_empty() {
        return None;
    }
    Some(start.trim())
}

fn definitely_gone(pid: i32, expected: &str, fields: Option<&str>) -> bool {
    if matches!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH)) {
        return true;
    }
    // A failed or malformed probe is unknown, not proof of exit.
    fields.is_some_and(|text| {
        text.starts_with('Z') || identity(text).is_some_and(|actual| actual != expected)
    })
}

pub async fn identify_owner(pid: i32) -> Option<OwnerProcess> {
    if pid <= 1 || u32::try_from(pid).ok() == Some(std::process::id()) {
        return None;
    }
    let fields = process_fields(pid, false).await?;
    let start_time = identity(&fields)?.to_owned();
    let exited = Arc::new(AtomicBool::new(false));
    let weak = Arc::downgrade(&exited);
    let expected = start_time.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if weak.strong_count() == 0 {
                return;
            }
            let fields = process_fields(pid, false).await;
            let Some(flag) = weak.upgrade() else {
                return;
            };
            if definitely_gone(pid, &expected, fields.as_deref()) {
                flag.store(true, Ordering::Release);
                return;
            }
        }
    });
    Some(OwnerProcess {
        pid,
        start_time,
        exited,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_probes_never_claim_exit_and_recycled_identity_does() {
        let pid = i32::try_from(std::process::id()).unwrap();
        assert!(!definitely_gone(pid, "start", None));
        assert!(!definitely_gone(pid, "start", Some("garbled")));
        assert!(!definitely_gone(pid, "start", Some("S start")));
        assert!(definitely_gone(pid, "start", Some("S newer")));
        assert!(definitely_gone(pid, "start", Some("Z start")));
    }
}
