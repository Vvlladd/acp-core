//! T79 (B3): the run-shape half — a v2 team's role subset drives which steps run, proven on
//! whole runs through fake providers, gate summaries and payloads included.

mod common;

use std::sync::Arc;

use agent_control_plane::core::team::{save_team, Team};
use agent_control_plane::core::types::{Event, EventPayload, GateKind, RoleName, RunId};
use agent_control_plane::core::GateResolution;
use serde_json::{json, Value};

use common::{
    cli_actor, delegate_builder, embedded_roles, loop_task, quiesce, start_actor, wait_for_log,
    ActorOpts, LoopWorld,
};

fn v2_team(value: Value) -> Team {
    serde_json::from_value(value).expect("a v2 team")
}

/// Roles of every `agent.created`, in log order.
fn spawned_roles(events: &[Arc<Event>]) -> Vec<RoleName> {
    events
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::AgentCreated { role, .. } => Some(*role),
            _ => None,
        })
        .collect()
}

/// `(gateId, summary, payloadPath)` of the run's integrate gate.
fn integrate_gate_row(
    events: &[Arc<Event>],
) -> Option<(
    agent_control_plane::core::types::GateId,
    String,
    std::path::PathBuf,
)> {
    events.iter().find_map(|event| match &event.payload {
        EventPayload::GateCreated {
            gate_id,
            gate_kind,
            summary,
            payload_path,
            ..
        } if *gate_kind == GateKind::Integrate => {
            Some((*gate_id, summary.clone(), payload_path.clone()))
        }
        _ => None,
    })
}

async fn run_to_gate(world: &LoopWorld, run: &RunId) -> Vec<Arc<Event>> {
    wait_for_log(world, run, "gate.created{integrate}", |events| {
        integrate_gate_row(events).is_some()
    })
    .await
}

/// A builder-only team: no verify, no review — one spawn, straight to a loud human gate whose
/// payload carries no verdict, and an approval that still commits exactly the frozen bytes.
#[test]
fn a_builder_only_team_goes_straight_to_a_loud_gate() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        save_team(
            world.state_dir(),
            &v2_team(json!({
                "version": 2,
                "name": "builder only",
                "roles": { "builder": { "provider": "claude", "model": "haiku" } }
            })),
        )
        .expect("save the v2 team");
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T79-solo")))
            .await
            .expect("delegate");
        let run = out.run_id;
        let events = run_to_gate(&world, &run).await;

        assert_eq!(
            spawned_roles(&events),
            [RoleName::Builder],
            "no verifier and no reviewer spawned for a builder-only team"
        );
        let (gate, summary, payload_path) = integrate_gate_row(&events).expect("the gate");
        assert!(
            summary.starts_with("NO reviewer ran"),
            "the gate says loudly that nothing reviewed this diff: {summary}"
        );
        let payload: Value = serde_json::from_str(
            &std::fs::read_to_string(&payload_path).expect("read the gate payload"),
        )
        .expect("gate payload JSON");
        assert!(
            payload["verdictPath"].is_null(),
            "no verdict may be claimed when no reviewer ran: {payload}"
        );

        let resolution = handle
            .resolve_gate(gate, true, None, cli_actor())
            .await
            .expect("the human approval still works");
        let GateResolution::Approved { sha: Some(sha) } = resolution else {
            panic!("the approval committed: {resolution:?}");
        };

        // The commit is read the way a human reads `git log`: the subject names the task, and the
        // loud no-reviewer sentence is the body's first line — not a 72-byte subject that pushes
        // the task title out (found in the B3 walkthrough).
        let message = commit_message(world.repo_root(), &sha);
        let mut lines = message.lines();
        assert_eq!(
            lines.next(),
            Some("acp: T79-solo: Add src/adder.ts exporting add(a, b)."),
            "the subject leads with the task: {message:?}"
        );
        assert_eq!(
            lines.next(),
            Some(""),
            "a blank line separates subject and body"
        );
        assert!(
            lines
                .next()
                .is_some_and(|line| line.starts_with("NO reviewer ran")),
            "the honesty sentence opens the body: {message:?}"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// `git log -1 --format=%B <sha>` from the repository root — the worktree shares its objects.
fn commit_message(repo: &std::path::Path, sha: &str) -> String {
    let out = std::process::Command::new("git")
        .args(["log", "-1", "--format=%B", sha])
        .current_dir(repo)
        .output()
        .expect("spawn git log");
    assert!(
        out.status.success(),
        "git log {sha} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Build + verify, no review: the verifier still runs and its line reaches the gate summary —
/// alongside the loud no-reviewer lead line.
#[test]
fn a_verify_on_review_off_team_keeps_the_verify_line() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        save_team(
            world.state_dir(),
            &v2_team(json!({
                "version": 2,
                "name": "build and verify",
                "roles": {
                    "builder": { "provider": "claude", "model": "haiku" },
                    "verifier": { "provider": "claude", "model": "haiku" }
                }
            })),
        )
        .expect("save the v2 team");
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T79-verify-only")))
            .await
            .expect("delegate");
        let run = out.run_id;
        let events = run_to_gate(&world, &run).await;

        assert_eq!(
            spawned_roles(&events),
            [RoleName::Builder, RoleName::Verifier],
            "the verifier ran; no reviewer did"
        );
        let (_, summary, _) = integrate_gate_row(&events).expect("the gate");
        assert!(
            summary.starts_with("NO reviewer ran"),
            "the no-reviewer line leads: {summary}"
        );
        assert!(
            summary.contains("Verified:"),
            "what verification found still reaches the human: {summary}"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}
