//! On-demand projection of a single worker's task messages and validated replies.
//! This projection never reads provider logs, command lines, system prompts or tool calls.
use super::policy::{PolicyCode, PolicyError};
use super::registry::Registry;
use super::types::{AgentId, AttemptId, Event, EventPayload, Origin, RoleName, RunId};
use super::{Command, CoreError, CoreHandle};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PAGE_EVENTS: usize = 256;
const PAGE_MESSAGES: usize = 12;
const MESSAGE_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub run_id: RunId,
    pub agent_id: AgentId,
    #[serde(default)]
    pub after_seq: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    run_id: RunId,
    agent_id: AgentId,
    messages: Vec<Message>,
    next_after_seq: Option<u64>,
    history_incomplete: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    seq: u64,
    attempt_id: AttemptId,
    sender: &'static str,
    recipient: &'static str,
    kind: &'static str,
    text: String,
    truncated: bool,
}

impl CoreHandle {
    /// Read the selected exchange through the human socket.
    pub async fn worker_transcript(&self, query: Query) -> Result<Page, CoreError> {
        self.ask(|reply| Command::WorkerTranscript { query, reply })
            .await
    }
}

/// Common status and subscription channels carry the event identity, so a viewer can
/// refresh its selected exchange without broadcasting the message to every observer.
pub(crate) fn notification_event(event: &Event) -> std::borrow::Cow<'_, Event> {
    if matches!(event.payload, EventPayload::WorkerMessage { .. } | EventPayload::AttemptStarted { .. }
        | EventPayload::WorktreeCreated { delegated_task: Some(_), .. }) {
        let mut marker = event.clone();
        match &mut marker.payload {
            EventPayload::WorkerMessage { text, truncated, .. } => {
                text.clear();
                *truncated = true;
            }
            // Provider argv contains the full prompt. Keep it in the private event log.
            EventPayload::AttemptStarted { argv, .. } => argv.clear(),
            EventPayload::WorktreeCreated { delegated_task, .. } => *delegated_task = None,
            _ => unreachable!("only transcript-bearing event kinds are redacted"),
        }
        return std::borrow::Cow::Owned(marker);
    }
    std::borrow::Cow::Borrowed(event)
}

fn role_label(role: RoleName) -> &'static str {
    match role {
        RoleName::Lead => "lead",
        RoleName::Builder => "builder",
        RoleName::Verifier => "verifier",
        RoleName::Reviewer => "reviewer",
        RoleName::Security => "security",
    }
}

/// Whole-field suppression avoids showing the rest of a credential across lines.
/// The data source is an intentionally small set of conversational fields; arbitrary
/// user-supplied prose is visible to the paired human and is never considered trusted.
fn display_text(text: &str) -> (String, bool) {
    let folded = text.to_ascii_lowercase();
    let credential_assignment = folded.match_indices(['=', ':']).any(|(i, _)| {
        let prefix = folded[..i].trim_end_matches([' ', '\t', '"', '\'']);
        let key = prefix
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .next()
            .unwrap_or_default()
            .replace('-', "_");
        [
            "password",
            "passwd",
            "token",
            "secret",
            "secret_access_key",
            "api_key",
            "apikey",
            "access_key_id",
            "authorization",
            "cookie",
            "session_key",
        ]
        .iter()
        .any(|suffix| key.ends_with(suffix))
    });
    if credential_assignment
        || [
            "private key-----",
            "authorization:",
            "bearer ",
            "sk-ant-",
            "sk-proj-",
            "github_pat_",
            "ghp_",
            "xoxb-",
            "xoxp-",
            "gho_",
            "ghs_",
            "access_token=",
            "api_key=",
            "password=",
            "api-key:",
            "#key=",
        ]
        .iter()
        .any(|needle| folded.contains(needle))
    {
        return (
            "[Message withheld because it may contain a credential.]".into(),
            true,
        );
    }
    let end = text.floor_char_boundary(MESSAGE_BYTES.min(text.len()));
    (text[..end].to_owned(), end < text.len())
}

pub(super) fn outbound(
    agent_id: AgentId,
    attempt_id: AttemptId,
    sender: Origin,
    followup: bool,
    body: &str,
) -> EventPayload {
    let (text, truncated) = display_text(body);
    EventPayload::WorkerMessage {
        agent_id,
        attempt_id,
        sender,
        followup,
        text,
        truncated,
    }
}

// Select human-readable fields out of the already validated schema. Command output,
// file contents, private model reasoning and provider-specific extensions stay out.
fn reply_text(role: RoleName, value: &Value) -> Option<String> {
    let lines: Vec<&str> = match role {
        RoleName::Builder | RoleName::Verifier => {
            let mut lines = vec![
                value.get("status")?.as_str()?,
                value.get("summary")?.as_str()?,
            ];
            if role == RoleName::Verifier {
                lines.extend(
                    value
                        .get("failures")?
                        .as_array()?
                        .iter()
                        .filter_map(Value::as_str),
                );
            }
            lines
        }
        RoleName::Reviewer | RoleName::Security => {
            let mut lines = vec![value.get("verdict")?.as_str()?];
            for finding in value.get("findings")?.as_array()? {
                lines.push(finding.get("problem")?.as_str()?);
                if let Some(fix) = finding.get("fix").and_then(Value::as_str) {
                    lines.push(fix);
                }
            }
            lines
        }
        RoleName::Lead => return None,
    };
    Some(lines.join("\n"))
}

pub(super) fn page(registry: &Registry, query: &Query) -> Result<Page, CoreError> {
    let agent = registry
        .agent(&query.agent_id)
        .filter(|agent| agent.run_id == query.run_id && agent.role != RoleName::Lead)
        .ok_or_else(|| PolicyError::new(PolicyCode::InvalidTask, "No such worker in this run"))?;
    let worker = role_label(agent.role);
    let mut messages = Vec::new();
    let mut cursor = query.after_seq;
    let mut history_incomplete = false;
    let role_is_review = matches!(agent.role, RoleName::Reviewer | RoleName::Security);
    let owns_attempt = |id: &AttemptId| {
        registry
            .attempt(id)
            .is_some_and(|a| a.agent_id == query.agent_id && a.run_id == query.run_id)
    };
    for event in registry.events(&query.run_id, Some(cursor), PAGE_EVENTS) {
        cursor = event.base.seq;
        let (attempt_id, sender, recipient, kind, body, clipped) = match &event.payload {
            EventPayload::WorkerMessage {
                agent_id,
                attempt_id,
                sender,
                followup,
                text,
                truncated,
            } if *agent_id == query.agent_id => (
                *attempt_id,
                if *sender == Origin::Lead {
                    "lead"
                } else {
                    "workflow"
                },
                worker,
                if *followup { "followup" } else { "task" },
                text.clone(),
                *truncated,
            ),
            EventPayload::AttemptStarted {
                agent_id,
                attempt_id,
                ..
            } if *agent_id == query.agent_id
                && !registry.state().worker_inputs.contains(&(
                    query.run_id,
                    query.agent_id,
                    *attempt_id,
                )) =>
            {
                (
                    *attempt_id,
                    "workflow",
                    worker,
                    "gap",
                    "The request for this attempt was not recorded.".into(),
                    false,
                )
            }
            EventPayload::AttemptResult {
                attempt_id,
                structured_valid,
                structured,
                ..
            } if owns_attempt(attempt_id) => {
                let body = structured
                    .as_ref()
                    .filter(|_| *structured_valid)
                    .and_then(|v| reply_text(agent.role, v));
                match body {
                    Some(body) => (
                        *attempt_id,
                        worker,
                        "lead",
                        if role_is_review { "review" } else { "result" },
                        body,
                        false,
                    ),
                    None => (
                        *attempt_id,
                        worker,
                        "lead",
                        "gap",
                        "No validated worker reply is available.".into(),
                        false,
                    ),
                }
            }
            EventPayload::AttemptFinished { attempt_id, .. }
                if owns_attempt(attempt_id)
                    && registry
                        .attempt(attempt_id)
                        .is_some_and(|a| a.structured_valid.is_none()) =>
            {
                (
                    *attempt_id,
                    worker,
                    "lead",
                    "gap",
                    "The attempt ended without a recorded reply.".into(),
                    false,
                )
            }
            _ => continue,
        };
        let (text, truncated) = display_text(&body);
        history_incomplete |= kind == "gap" || truncated || clipped;
        messages.push(Message {
            seq: cursor,
            attempt_id,
            sender,
            recipient,
            kind,
            text,
            truncated: truncated || clipped,
        });
        if messages.len() == PAGE_MESSAGES {
            break;
        }
    }
    let more = registry
        .run(&query.run_id)
        .is_some_and(|r| cursor < r.last_seq);
    Ok(Page {
        run_id: query.run_id,
        agent_id: query.agent_id,
        messages,
        next_after_seq: more.then_some(cursor),
        history_incomplete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn add(reg: &mut Registry, run: RunId, value: Value) {
        reg.append(&run, serde_json::from_value(value).unwrap())
            .unwrap();
    }

    #[test]
    fn replay_pages_preserve_order_mark_missing_inputs_and_isolate_other_workers() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = Registry::open(dir.path()).unwrap();
        let run = RunId::new_v4();
        let worker = AgentId::new_v4();
        let other = AgentId::new_v4();
        let attempt = AttemptId::new_v4();
        add(
            &mut reg,
            run,
            json!({"kind":"run.created", "repoRoot":"/repo", "stateDir":"/state",
            "baseRef":"main","baseSha":"abc","task":{"id":"t","title":"task","description":"test","files":[],"acceptance":[]},
            "version":1,"lead":null,"teamName":null}),
        );
        for id in [worker, other] {
            add(
                &mut reg,
                run,
                json!({"kind":"agent.created","agentId":id,"role":"builder","provider":"claude",
                "model":"test","lineageId":null,"depth":1,"parentAgentId":null,"origin":"lead","writes":true,
                "cwd":"/repo","worktree":"/repo"}),
            );
        }
        add(
            &mut reg,
            run,
            json!({"kind":"attempt.started","attemptId":attempt,"agentId":worker,
            "kind2":"fresh","dir":"/private/state","argv":["HIDDEN-LEGACY-PROMPT"],"cwd":"/repo",
            "pid":1,"pgid":1,"startTime":"test","preSha":"a","timeoutSec":1,"spawnBudgetUsd":1.0}),
        );
        for i in 0..(PAGE_MESSAGES + 2) {
            for (id, body) in [
                (other, "another worker".into()),
                (worker, format!("Turn {i}")),
            ] {
                reg.append(
                    &run,
                    outbound(id, AttemptId::new_v4(), Origin::Lead, true, &body),
                )
                .unwrap();
            }
        }
        drop(reg);
        let reg = Registry::open(dir.path()).unwrap();
        let mut query = Query {
            run_id: run,
            agent_id: worker,
            after_seq: 0,
        };
        let first = page(&reg, &query).unwrap();
        assert_eq!(first.messages.len(), PAGE_MESSAGES);
        assert!(first.history_incomplete);
        assert_eq!(first.messages[0].kind, "gap");
        query.after_seq = first.next_after_seq.unwrap();
        let second = page(&reg, &query).unwrap();
        assert_eq!(second.next_after_seq, None);
        assert!(!second.history_incomplete);
        let rows: Vec<_> = first.messages.iter().chain(&second.messages).collect();
        assert!(rows.windows(2).all(|w| w[0].seq < w[1].seq));
        assert_eq!(rows.len(), 1 + PAGE_MESSAGES + 2);
        assert!(rows.iter().all(
            |m| !m.text.contains("HIDDEN-LEGACY-PROMPT") && !m.text.contains("another worker")
        ));
    }

    #[test]
    fn a_secret_or_a_long_message_cannot_be_returned_verbatim() {
        for text in [
            "Authorization: Bearer test",
            "-----BEGIN PRIVATE KEY-----\nexample",
            "Open http://127.0.0.1/#key=sample",
            "AWS_SECRET_ACCESS_KEY = example",
            "password: example",
            r#"{"refresh_token" : "example"}"#,
            "X-API-Key : example",
        ] {
            let (body, clipped) = display_text(text);
            assert!(clipped);
            assert!(!body.contains(text));
        }
        let body = "日".repeat(MESSAGE_BYTES);
        let (limited, clipped) = display_text(&body);
        assert!(clipped && limited.len() <= MESSAGE_BYTES);
        assert!(body.starts_with(&limited));
    }
}
