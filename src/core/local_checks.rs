//! Admission and durable summaries for advisory local inspections. No integration authority.
use super::*;
use crate::checks::{self, Request, Summary};
use serde_json::{json, Value};
use uuid::Uuid;

pub(super) struct Pending {
    summary: Summary,
    cancel: CancellationToken,
}
fn error(reason: impl Into<String>) -> CoreError {
    CoreError::Lifecycle {
        code: "check_failed",
        reason: reason.into(),
    }
}
impl Core {
    pub(super) fn start_check(&mut self, request: Request) -> Result<Summary, CoreError> {
        checks::validate(&request).map_err(error)?;
        if let Some(pending) = self.local_checks.get(&request.id) {
            return if pending.summary.request == request {
                Ok(pending.summary.clone())
            } else {
                Err(error("Review ID is already used for different input"))
            };
        }
        if checks::directory(&self.state_dir, request.id).exists() {
            let mut summary = checks::read_summary(&self.state_dir, request.id).map_err(error)?;
            return if summary.request == request {
                checks::mark_interrupted(&mut summary);
                Ok(summary)
            } else {
                Err(error("Review ID is already used for different input"))
            };
        }
        if !self.local_checks.is_empty() {
            return Err(error(
                "A local review is already running; wait or cancel it first",
            ));
        }
        let summary = Summary {
            id: request.id,
            request: request.clone(),
            created_at: registry::now_rfc3339(),
            status: "running".into(),
            detail: "Capturing source and running local checks".into(),
            file_count: 0,
            finding_count: 0,
            report_hash: None,
        };
        checks::append(&self.state_dir, &summary).map_err(error)?;
        let cancel = CancellationToken::new();
        self.local_checks.insert(
            request.id,
            Pending {
                summary: summary.clone(),
                cancel: cancel.clone(),
            },
        );
        let repo = self.repo_root.clone();
        let state = self.state_dir.clone();
        let tx = self.tx.clone();
        let lock = self.supervisor.worktree_lock(&repo);
        tokio::spawn(async move {
            let _guard = lock.lock().await;
            let id = request.id;
            let result = match checks::execute(repo, state.clone(), request, cancel).await {
                Ok(report) => tokio::task::spawn_blocking(move || {
                    checks::persist_report(&state, id, &report).map(|hash| (report, hash))
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string())),
                Err(e) => Err(e),
            };
            let _ = tx.send(Command::CheckFinished { id, result }).await;
        });
        Ok(summary)
    }
    pub(super) fn cancel_check(&mut self, id: Uuid) -> Result<Summary, CoreError> {
        if let Some(pending) = self.local_checks.get(&id) {
            pending.cancel.cancel();
            return Ok(pending.summary.clone());
        }
        checks::read_summary(&self.state_dir, id).map_err(error)
    }
    pub(super) fn cancel_local_checks(&self) {
        for pending in self.local_checks.values() {
            pending.cancel.cancel();
        }
    }
    pub(super) fn finish_check(
        &mut self,
        id: Uuid,
        result: Result<(checks::Report, String), String>,
    ) {
        let Some(pending) = self.local_checks.get(&id) else {
            return;
        };
        let mut summary = pending.summary.clone();
        if pending.cancel.is_cancelled() {
            summary.status = "cancelled".into();
            summary.detail = "Review cancelled. No changes were made.".into();
        } else {
            match result {
                Ok((report, hash)) => {
                    summary.status = if report.partial {
                        "partial"
                    } else {
                        "completed"
                    }
                    .into();
                    summary.file_count = report.files.len();
                    summary.finding_count = report.findings.len();
                    summary.report_hash = Some(hash);
                    summary.detail=if report.partial{"Some source could not be fully analyzed; findings cover only the reported syntax."}
                    else if report.files.is_empty(){"No Swift source matched this scope. No checks were run."}
                    else{"Local syntax review complete. Findings are advisory; this is not a build or correctness guarantee."}.into();
                }
                Err(reason) => {
                    summary.status = "failed".into();
                    summary.detail = reason.chars().take(2000).collect();
                }
            }
        }
        match checks::append(&self.state_dir, &summary) {
            Ok(()) => {
                self.local_checks.remove(&id);
            }
            Err(reason) => {
                self.fatal = Some(format!("Cannot persist local review outcome: {reason}"));
            }
        }
    }
    pub(super) fn list_checks(&self, offset: usize, reply: Reply<Value>) {
        let state = self.state_dir.clone();
        let active = self.local_checks.keys().copied().collect();
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                checks::restored(&state, &active).and_then(|reviews| {
                    if offset > reviews.len() { return Err("Invalid history offset".into()); }
                    let end = (offset + 50).min(reviews.len());
                    Ok(json!({"reviews": &reviews[offset..end], "nextOffset": (end < reviews.len()).then_some(end)}))
                })
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()))
            .map_err(error);
            let _ = reply.send(result);
        });
    }
}
