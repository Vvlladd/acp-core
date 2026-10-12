//! T68 (C1): a **codex builder** drives the full loop end to end under the measured
//! workspace-write seatbelt — team-selected, spawned with the six confinement items, its diff
//! frozen, verified, reviewed, human-approved and committed — plus the codex-verifier team shape.
//!
//! Same harness rules as `tests/loop_pass.rs`. The writing codex call is argv-selected inside
//! `fake-codex` (workspace-write tokens → the build transcript + the real worktree write), so
//! the reviewer scenario keeps steering reviews untouched.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use agent_control_plane::core::team::{save_team, Assignment, Effort, Team};
use agent_control_plane::core::types::{
    AgentId, AttemptStatus, Event, EventPayload, GateKind, ProviderName, RoleName,
};
use agent_control_plane::core::GateResolution;
use serde_json::Value;

use common::{
    await_done, cli_actor, delegate_builder, embedded_roles, files_in_commit, head_sha, loop_task,
    pick, quiesce, start_actor, wait_for_log, ActorOpts, LoopWorld,
};

/// A v1 team assigning exactly one role.
fn team_of(role: &str, provider: ProviderName, model: &str, effort: Option<Effort>) -> Team {
    let mut roles = BTreeMap::new();
    roles.insert(
        role.to_string(),
        Assignment {
            provider,
            model: model.to_string(),
            effort,
        },
    );
    Team {
        mode: None,
        // v1 on purpose: this helper overrides ONE role and leans on the defaults for the rest,
        // which is exactly v1's absence semantics. A v2 team would demand explicit membership
        // (and a builder entry) — the subset behavior has its own suite.
        version: 1,
        name: format!("codex {role}"),
        lead: None,
        roles,
    }
}

/// `(agent_id, argv, cwd)` of every `attempt.started`, in log order.
fn attempts_started(events: &[Arc<Event>]) -> Vec<(AgentId, Vec<String>, PathBuf)> {
    pick(events, |p| match p {
        EventPayload::AttemptStarted {
            agent_id,
            argv,
            cwd,
            ..
        } => Some((*agent_id, argv.clone(), cwd.clone())),
        _ => None,
    })
}

fn agents_of(events: &[Arc<Event>], role: RoleName) -> Vec<AgentId> {
    pick(events, |p| match p {
        EventPayload::AgentCreated {
            agent_id,
            role: created,
            ..
        } if *created == role => Some(*agent_id),
        _ => None,
    })
}

/// The six measured confinement items (research § 2, items 1-6) plus the fresh-path `-s`.
fn assert_workspace_write_shape(
    argv: &[String],
    cwd: &std::path::Path,
    worktree: &std::path::Path,
) {
    let strs: Vec<&str> = argv.iter().map(String::as_str).collect();
    for token in [
        "-s",
        "workspace-write",
        r#"sandbox_mode="workspace-write""#,
        "sandbox_workspace_write.exclude_slash_tmp=true",
        "sandbox_workspace_write.exclude_tmpdir_env_var=true",
        "sandbox_workspace_write.writable_roots=[]",
        "--ignore-user-config",
    ] {
        assert!(strs.contains(&token), "missing {token} in {strs:?}");
    }
    assert_eq!(cwd, worktree, "cwd pins the writable root");
}

/// The flip's whole point, end to end: `team.json` moves the builder to codex, the spawn carries
/// the measured seatbelt, and the loop completes through verify, review, human approval and a
/// commit of exactly the reviewed bytes.
#[test]
fn a_codex_builder_drives_the_full_loop_sandboxed_to_an_approved_commit() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        save_team(
            world.state_dir(),
            &team_of("builder", ProviderName::Codex, "gpt-5.5", Some(Effort::Low)),
        )
        .expect("a codex builder team is savable since C1");
        let base_sha = head_sha(world.repo_root());
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T68-codex-builder")))
            .await
            .expect("a codex builder team delegates since C1");
        let run = out.run_id;

        let envelope = await_done(&handle, out.agent_id).await;
        assert_eq!(envelope.status, AttemptStatus::Succeeded, "{envelope:?}");
        assert_eq!(
            envelope.provider,
            ProviderName::Codex,
            "the team chose codex"
        );
        assert_eq!(
            envelope
                .structured
                .as_ref()
                .and_then(|s| s.get("status"))
                .and_then(Value::as_str),
            Some("succeeded")
        );

        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !pick(events, |p| match p {
                EventPayload::GateCreated {
                    gate_kind: GateKind::Integrate,
                    gate_id,
                    ..
                } => Some(*gate_id),
                _ => None,
            })
            .is_empty()
        })
        .await;

        // The builder's spawn argv is the measured plan, item by item, and its cwd is the
        // worktree that pins the writable root.
        let (_, argv, cwd) = attempts_started(&events)
            .into_iter()
            .find(|(agent, _, _)| *agent == out.agent_id)
            .expect("the builder attempt started");
        assert_workspace_write_shape(&argv, &cwd, &out.worktree);

        // The verify step ran on the default claude verifier, and the reviewer on codex — a
        // three-provider-role loop with the team steering only what it named.
        assert_eq!(agents_of(&events, RoleName::Verifier).len(), 1);
        let reviewers = agents_of(&events, RoleName::Reviewer);
        assert_eq!(reviewers.len(), 1);
        // T68's read-only regression: the SAME run mixes the modes correctly — the codex
        // reviewer's spawn carries none of the workspace-write tokens.
        let (_, reviewer_argv, _) = attempts_started(&events)
            .into_iter()
            .find(|(agent, _, _)| reviewers.contains(agent))
            .expect("the reviewer attempt started");
        for token in [
            "workspace-write",
            "sandbox_workspace_write.exclude_slash_tmp=true",
            "sandbox_workspace_write.exclude_tmpdir_env_var=true",
            "sandbox_workspace_write.writable_roots=[]",
        ] {
            assert!(
                !reviewer_argv.iter().any(|t| t == token),
                "the read-only reviewer must not carry {token}"
            );
        }

        let gate_id = pick(&events, |p| match p {
            EventPayload::GateCreated {
                gate_kind: GateKind::Integrate,
                gate_id,
                ..
            } => Some(*gate_id),
            _ => None,
        })[0];
        let resolution = handle
            .resolve_gate(gate_id, true, None, cli_actor())
            .await
            .expect("the approval is answered");
        let GateResolution::Approved { sha: Some(sha) } = resolution else {
            panic!("the gate resolved as {resolution:?}");
        };
        assert_ne!(sha, base_sha);
        assert_eq!(
            files_in_commit(&out.worktree, &sha),
            vec!["src/adder.ts"],
            "the commit is exactly what the codex builder wrote and the reviewer saw"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// A codex **verifier** team is accepted since C1 and its spawn carries the same measured shape
/// into the builder's worktree. The report itself is not driven to completion here — the shape
/// at the chokepoint is this test's subject; the verify outcomes are T65's.
#[test]
fn a_codex_verifier_team_spawns_with_the_workspace_write_shape() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        save_team(
            world.state_dir(),
            &team_of(
                "verifier",
                ProviderName::Codex,
                "gpt-5.5",
                Some(Effort::Low),
            ),
        )
        .expect("a codex verifier team is savable since C1");
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let out = handle
            .delegate(delegate_builder(loop_task("T68-codex-verifier")))
            .await
            .expect("a codex verifier team delegates since C1");
        let run = out.run_id;

        let events = wait_for_log(
            &world,
            &run,
            "the codex verifier attempt starts",
            |events| {
                let verifiers = agents_of(events, RoleName::Verifier);
                attempts_started(events)
                    .iter()
                    .any(|(agent, _, _)| verifiers.contains(agent))
            },
        )
        .await;
        let verifiers = agents_of(&events, RoleName::Verifier);
        let (_, argv, cwd) = attempts_started(&events)
            .into_iter()
            .find(|(agent, _, _)| verifiers.contains(agent))
            .expect("the verifier attempt");
        assert_workspace_write_shape(&argv, &cwd, &out.worktree);

        // Enough proven — the argv shape at the chokepoint is this test's subject; end the run
        // rather than drive a codex verify report to completion (T65 owns verify outcomes).
        quiesce(&handle).await;
        actor.stop().await;
    });
}
