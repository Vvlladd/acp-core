//! T65 (B1): the verify step, end to end through the whole actor — the four report outcomes
//! (`pass`, `fail`, `nothing-to-run`, wrong hash), the per-diff replacement cap, a restart across
//! a live verify step, and the compat path for a roles config without a verifier.
//!
//! Same harness rules as `tests/loop_pass.rs`: real `Core`, real spawns of the fake CLIs via the
//! wrapper scripts, waits on the durable log only, every worker quiesced before a test returns.
//! The verifier's transcript is selected by `ACP_FAKE_VERIFY_SCENARIO` and its `diffHash` is
//! lifted from the verifier's own prompt by the claude wrapper (`ACP_FAKE_VERIFY_HASH`) — a test
//! that wants the mismatch path pins that variable instead, exactly as the reviewer tests pin
//! `ACP_FAKE_DIFF_HASH`.

mod common;

use std::sync::Arc;

use agent_control_plane::core::types::{
    AgentId, AttemptKind, AttemptStatus, ErrorCode, Event, EventPayload, GateKind, RoleName,
    RunStatus, VerifyStatus,
};
use agent_control_plane::core::StatusQuery;

use agent_control_plane::core::handoff::ADVISORY_OPEN;
use common::{
    delegate_builder, embedded_roles, loop_task, pick, quiesce, rendered_prompt, start_actor,
    wait_for_log, wait_for_status, ActorOpts, LoopWorld,
};

/// 64 hex chars that are a well-formed hash and provably not the frozen diff's.
const WRONG_VERIFY_HASH: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

// ---------------------------------------------------------------------------
// Log queries
// ---------------------------------------------------------------------------

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

/// Every `verify.report`, as `(status, summary, failures)`, in log order.
fn verify_reports(events: &[Arc<Event>]) -> Vec<(VerifyStatus, String, Vec<String>)> {
    pick(events, |p| match p {
        EventPayload::VerifyReport {
            status,
            summary,
            failures,
            ..
        } => Some((*status, summary.clone(), failures.clone())),
        _ => None,
    })
}

fn gate_summaries(events: &[Arc<Event>], kind: GateKind) -> Vec<String> {
    pick(events, |p| match p {
        EventPayload::GateCreated {
            gate_kind: created,
            summary,
            ..
        } if *created == kind => Some(summary.clone()),
        _ => None,
    })
}

fn strike_reasons(events: &[Arc<Event>]) -> Vec<String> {
    pick(events, |p| match p {
        EventPayload::LineageStrike { reason, .. } => Some(reason.clone()),
        _ => None,
    })
}

/// `seq` of the first event matching `pred`, or a panic naming `what`.
fn seq_of(events: &[Arc<Event>], what: &str, pred: impl Fn(&EventPayload) -> bool) -> u64 {
    events
        .iter()
        .find(|e| pred(&e.payload))
        .unwrap_or_else(|| panic!("no event matched: {what}"))
        .base
        .seq
}

// ---------------------------------------------------------------------------
// The four report outcomes
// ---------------------------------------------------------------------------

/// The plan's own acceptance line: the pass path shows `verify.report` **strictly between** the
/// builder's terminal event and the review verdict, and the human's gate card carries the verify
/// line. Durable order, read off the log — never off a snapshot.
#[test]
fn a_verify_pass_sits_between_the_build_and_the_review_and_reaches_the_gate_card() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let run = handle
            .delegate(delegate_builder(loop_task("T65-pass")))
            .await
            .expect("delegate")
            .run_id;
        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !gate_summaries(events, GateKind::Integrate).is_empty()
        })
        .await;

        assert_eq!(agents_of(&events, RoleName::Verifier).len(), 1);
        let reports = verify_reports(&events);
        assert_eq!(reports.len(), 1, "one verify.report, emitted exactly once");
        assert_eq!(reports[0].0, VerifyStatus::Pass);

        let build_done = seq_of(&events, "the builder's success", |p| {
            matches!(
                p,
                EventPayload::AttemptFinished {
                    status: AttemptStatus::Succeeded,
                    ..
                }
            )
        });
        let report = seq_of(&events, "verify.report", |p| {
            matches!(p, EventPayload::VerifyReport { .. })
        });
        let verdict = seq_of(&events, "review.verdict", |p| {
            matches!(p, EventPayload::ReviewVerdict { .. })
        });
        assert!(
            build_done < report && report < verdict,
            "verify.report must sit strictly between the build and the review \
             (build={build_done}, report={report}, verdict={verdict})"
        );

        let summary = &gate_summaries(&events, GateKind::Integrate)[0];
        assert!(
            summary.contains("Verified: pass"),
            "the gate card tells the human what verification found: {summary:?}"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// A verify FAIL is a 17b strike on the **builder**: the same session is repaired (never
/// replaced), the strike reason names the failure count, and after the repair the second verify
/// passes and the loop completes. `verify_fail_then_pass` replays fail on the first verifier
/// invocation and pass on the second.
#[test]
fn a_verify_fail_strikes_the_builder_and_the_repaired_change_passes() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new(
            "pass",
            &[("ACP_FAKE_VERIFY_SCENARIO", "verify_fail_then_pass")],
        );
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let run = handle
            .delegate(delegate_builder(loop_task("T65-fail")))
            .await
            .expect("delegate")
            .run_id;
        // Staged waits: five sequential spawns share this arc, and each stage getting its own
        // deadline both survives the bimodal cold-spawn latency and names the stage that hung.
        wait_for_log(&world, &run, "the first verify report (fail)", |events| {
            !verify_reports(events).is_empty()
        })
        .await;
        wait_for_log(&world, &run, "the strike lands", |events| {
            !strike_reasons(events).is_empty()
        })
        .await;
        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !gate_summaries(events, GateKind::Integrate).is_empty()
        })
        .await;

        let reports = verify_reports(&events);
        assert_eq!(
            reports.iter().map(|(s, _, _)| *s).collect::<Vec<_>>(),
            [VerifyStatus::Fail, VerifyStatus::Pass],
            "first verify fails, the repaired change passes"
        );
        assert!(
            reports[0]
                .2
                .iter()
                .any(|line| line == "tests::adder_returns_sum"),
            "the failure lines are recorded verbatim: {:?}",
            reports[0].2
        );

        let reasons = strike_reasons(&events);
        assert_eq!(reasons.len(), 1, "exactly one strike");
        assert!(
            reasons[0].contains("verification failed"),
            "attributed to verification: {reasons:?}"
        );
        assert_eq!(
            agents_of(&events, RoleName::Builder).len(),
            1,
            "the builder is repaired in place, never replaced"
        );

        // The acceptance criterion, at the rendered-argv level: the repair prompt the builder
        // actually received carries the verifier's failure text verbatim, inside the advisory
        // block — the composition of StrikeCause::VerifyFail and build_verify_repair_prompt,
        // not just each half in isolation.
        let resumed: Vec<std::path::PathBuf> = pick(&events, |p| match p {
            EventPayload::AttemptStarted {
                attempt_kind: AttemptKind::Resume,
                dir,
                ..
            } => Some(dir.clone()),
            _ => None,
        });
        assert_eq!(resumed.len(), 1, "the repair is a resume of the same session");
        let prompt = rendered_prompt(&resumed[0]);
        assert!(
            prompt.contains("tests::adder_returns_sum")
                && prompt.contains("error[E0308]: mismatched types in src/adder.ts:2"),
            "the repair prompt carries the verifier's failure text verbatim: {prompt}"
        );
        assert!(
            prompt.contains(ADVISORY_OPEN),
            "…quoted as data, never as instructions (S3)"
        );

        assert_eq!(agents_of(&events, RoleName::Verifier).len(), 2);
        assert_eq!(agents_of(&events, RoleName::Reviewer).len(), 1);

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// A repo with no build/test command must never fail verification for it: `nothing-to-run`
/// proceeds to review, and the gate card says so.
#[test]
fn nothing_to_run_proceeds_to_review_and_the_gate_says_so() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[("ACP_FAKE_VERIFY_SCENARIO", "verify_nothing")]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let run = handle
            .delegate(delegate_builder(loop_task("T65-nothing")))
            .await
            .expect("delegate")
            .run_id;
        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !gate_summaries(events, GateKind::Integrate).is_empty()
        })
        .await;

        let reports = verify_reports(&events);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].0, VerifyStatus::NothingToRun);
        assert_eq!(agents_of(&events, RoleName::Reviewer).len(), 1);
        assert!(strike_reasons(&events).is_empty(), "never a strike for it");
        assert!(
            gate_summaries(&events, GateKind::Integrate)[0].contains("Verified: nothing to run"),
            "the human is told verification had nothing to check"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}

#[test]
fn environment_blocked_is_recorded_without_retry_repair_or_strike() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[("ACP_FAKE_VERIFY_SCENARIO", "verify_blocked")]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();
        let run = handle.delegate(delegate_builder(loop_task("T65-blocked")))
            .await.expect("delegate").run_id;
        wait_for_status(
            &handle,
            StatusQuery { run_id: Some(run), ..StatusQuery::default() },
            "environment-blocked verification",
            |s| s.runs.first().is_some_and(|r| r.status == RunStatus::Blocked),
        ).await;
        let events = world.events(&run);
        assert_eq!(verify_reports(&events).len(), 1);
        assert_eq!(verify_reports(&events)[0].0, VerifyStatus::Blocked);
        assert_eq!(agents_of(&events, RoleName::Verifier).len(), 1, "no equivalent retry");
        assert!(agents_of(&events, RoleName::Reviewer).is_empty());
        assert!(strike_reasons(&events).is_empty(), "environment blockers are not builder strikes");
        assert!(gate_summaries(&events, GateKind::Integrate).is_empty());
        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// Matching host hashes are insufficient if source changed after the reviewed diff was frozen.
#[test]
fn external_host_evidence_rejects_changes_before_the_first_host_inventory() {
    common::with_shared_env(|| async {
        use agent_control_plane::core::types::{Actor, ExternalCommandResult,
            ExternalCommandStatus, ExternalVerificationEvidence};
        use agent_control_plane::workspace::git;
        for change_source in ["file", "empty_directory", "none"] {
            let world = LoopWorld::new("pass", &[("ACP_FAKE_VERIFY_SCENARIO", "verify_blocked")]);
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            let handle = actor.handle.clone();
            let run = handle.delegate(delegate_builder(loop_task("T65-host-binding")))
                .await.unwrap().run_id;
            wait_for_status(&handle, StatusQuery { run_id: Some(run), ..StatusQuery::default() },
                "blocked verification", |s| s.runs.first().is_some_and(|r| r.status == RunStatus::Blocked)).await;
            let registry = world.reopen();
            let events = registry.events(&run, None, usize::MAX);
            let (attempt, diff_hash) = events.iter().rev().find_map(|e| match &e.payload {
                EventPayload::DiffFrozen { attempt_id, diff_hash, .. } => Some((*attempt_id, diff_hash.clone())),
                _ => None,
            }).unwrap();
            let commands = events.iter().rev().find_map(|e| match &e.payload {
                EventPayload::VerifyReport { commands, .. } => Some(commands.clone()), _ => None,
            }).unwrap();
            let worktree = registry.agent(&registry.attempt(&attempt).unwrap().agent_id)
                .unwrap().worktree.as_ref().unwrap();
            match change_source {
                "file" => std::fs::write(worktree.join("changed-after-freeze.txt"),
                    "untested frozen source\n").unwrap(),
                "empty_directory" => std::fs::create_dir(worktree.join("empty-after-freeze")).unwrap(),
                "none" => {}
                _ => unreachable!(),
            }
            let inventory = git::source_inventory_hash(worktree).await.unwrap();
            let seq = registry.run(&run).unwrap().last_seq;
            let result = handle.prepare_external_verification(run, ExternalVerificationEvidence {
                builder_attempt_id: attempt, diff_hash, expected_run_seq: seq,
                commands: commands.iter().map(|command| ExternalCommandResult {
                    worker_command: command.clone(), argv: vec!["cargo".into(), "test".into(), "--locked".into()],
                    status: ExternalCommandStatus::Passed, exit_status: Some(0),
                }).collect(),
                toolchain_identity: "fake host test toolchain".into(), provenance: "disposable regression fixture".into(),
                source_inventory_before_hash: inventory.clone(), source_inventory_after_hash: inventory,
                attestation: "Regression fixture attestation only".into(), limitations: vec!["fake providers".into()],
            }, Actor::Socket { client_name: "test-human".into() }).await;
            quiesce(&handle).await;
            actor.stop().await;
            if change_source != "none" {
                assert!(result.is_err(), "source changed after freeze was accepted: {result:?}");
                assert!(world.events(&run).iter().all(|event| !matches!(&event.payload,
                    EventPayload::GateResolving { external_verification: Some(_), .. })));
            } else {
                assert!(result.is_ok(), "unchanged frozen source was refused: {result:?}");
            }
        }
    });
}

/// Accepting host evidence is distinct from the integration gate, even with all reviews off.
#[test]
fn host_evidence_without_reviews_opens_one_pending_integration_gate_across_restart() {
    common::with_shared_env(|| async {
        use agent_control_plane::core::team::{save_team, Team};
        use agent_control_plane::core::types::{Actor, ExternalCommandResult,
            ExternalCommandStatus, ExternalVerificationEvidence, GateStatus};
        use agent_control_plane::workspace::git;

        let world = LoopWorld::new("pass", &[("ACP_FAKE_VERIFY_SCENARIO", "verify_blocked")]);
        let team: Team = serde_json::from_value(serde_json::json!({
            "version": 2,
            "name": "host evidence without reviews",
            "roles": {
                "builder": { "provider": "claude", "model": "haiku" },
                "verifier": { "provider": "claude", "model": "haiku" }
            }
        })).unwrap();
        save_team(world.state_dir(), &team).unwrap();
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();
        let run = handle.delegate(delegate_builder(loop_task("T65-host-no-review")))
            .await.unwrap().run_id;
        wait_for_status(&handle, StatusQuery { run_id: Some(run), ..StatusQuery::default() },
            "blocked verification", |s| s.runs.first().is_some_and(|r| r.status == RunStatus::Blocked)).await;
        let registry = world.reopen();
        let events = registry.events(&run, None, usize::MAX);
        let (attempt, diff_hash) = events.iter().rev().find_map(|e| match &e.payload {
            EventPayload::DiffFrozen { attempt_id, diff_hash, .. } => Some((*attempt_id, diff_hash.clone())),
            _ => None,
        }).unwrap();
        let commands = events.iter().rev().find_map(|e| match &e.payload {
            EventPayload::VerifyReport { commands, .. } => Some(commands.clone()), _ => None,
        }).unwrap();
        let worktree = registry.agent(&registry.attempt(&attempt).unwrap().agent_id)
            .unwrap().worktree.as_ref().unwrap();
        let inventory = git::source_inventory_hash(worktree).await.unwrap();
        let accepted = handle.prepare_external_verification(run, ExternalVerificationEvidence {
            builder_attempt_id: attempt, diff_hash,
            expected_run_seq: registry.run(&run).unwrap().last_seq,
            commands: commands.iter().map(|command| ExternalCommandResult {
                worker_command: command.clone(), argv: vec!["cargo".into(), "test".into()],
                status: ExternalCommandStatus::Passed, exit_status: Some(0),
            }).collect(),
            toolchain_identity: "fake host test toolchain".into(),
            provenance: "disposable regression fixture".into(),
            source_inventory_before_hash: inventory.clone(), source_inventory_after_hash: inventory,
            attestation: "Regression fixture attestation only".into(),
            limitations: vec!["fake providers".into()],
        }, Actor::Socket { client_name: "test-human".into() }).await.unwrap();
        wait_for_status(&handle, StatusQuery { run_id: Some(run), ..StatusQuery::default() },
            "awaiting integration", |s| s.runs.first().is_some_and(|r| r.status == RunStatus::AwaitingGate)).await;
        quiesce(&handle).await;
        actor.stop().await;

        let assert_gate = || {
            let registry = world.reopen();
            assert_eq!(registry.gate(&accepted.gate_id).unwrap().status, GateStatus::Approved);
            let gates: Vec<_> = registry.state().gates.values()
                .filter(|gate| gate.run_id == run && gate.kind == GateKind::Integrate).collect();
            assert_eq!(gates.len(), 1, "approved evidence must lead to exactly one integration gate");
            assert_eq!(gates[0].status, GateStatus::Pending, "evidence cannot approve integration");
            let events = registry.events(&run, None, usize::MAX);
            assert_eq!(gate_summaries(&events, GateKind::Integrate).len(), 1);
            assert!(gate_summaries(&events, GateKind::Integrate)[0].starts_with("NO reviewer ran"));
            assert!(agents_of(&events, RoleName::Reviewer).is_empty());
            assert!(agents_of(&events, RoleName::Security).is_empty());
            assert!(strike_reasons(&events).is_empty());
        };
        assert_gate();
        for _ in 0..2 {
            let actor = start_actor(&world, embedded_roles(), ActorOpts { reattach: true, ..ActorOpts::default() });
            quiesce(&actor.handle).await;
            actor.stop().await;
            assert_gate();
        }
    });
}

/// A crash can leave the external gate pending between preparation and immediate approval.
/// Resolving that durable gate must check the checkout as it is now under the shared lock.
#[test]
fn pending_host_evidence_after_restart_recaptures_the_checkout_before_approval() {
    common::with_shared_env(|| async {
        use agent_control_plane::core::gates::{self, GatePayload, NewGate};
        use agent_control_plane::core::types::{ExternalCommandResult, ExternalCommandStatus,
            ExternalVerificationEvidence, GateStatus, Origin};
        use agent_control_plane::workspace::git;
        for (changed, deny) in [(true, false), (false, false), (false, true)] {
            let world = LoopWorld::new("pass", &[("ACP_FAKE_VERIFY_SCENARIO", "verify_blocked")]);
            let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
            let run = actor.handle.delegate(delegate_builder(loop_task("T65-pending-host"))).await.unwrap().run_id;
            wait_for_status(&actor.handle, StatusQuery { run_id: Some(run), ..StatusQuery::default() },
                "blocked verification", |s| s.runs.first().is_some_and(|r| r.status == RunStatus::Blocked)).await;
            quiesce(&actor.handle).await;
            actor.stop().await;

            let mut registry = world.reopen();
            let events = registry.events(&run, None, usize::MAX);
            let (attempt, diff_hash) = events.iter().rev().find_map(|e| match &e.payload {
                EventPayload::DiffFrozen { attempt_id, diff_hash, .. } => Some((*attempt_id, diff_hash.clone())),
                _ => None,
            }).unwrap();
            let commands = events.iter().rev().find_map(|e| match &e.payload {
                EventPayload::VerifyReport { commands, .. } => Some(commands.clone()), _ => None,
            }).unwrap();
            let worktree = registry.agent(&registry.attempt(&attempt).unwrap().agent_id)
                .unwrap().worktree.clone().unwrap();
            let inventory = git::source_inventory_hash(&worktree).await.unwrap();
            let evidence = ExternalVerificationEvidence {
                builder_attempt_id: attempt, diff_hash, expected_run_seq: registry.run(&run).unwrap().last_seq,
                commands: commands.into_iter().map(|worker_command| ExternalCommandResult {
                    worker_command, argv: vec!["cargo".into(), "test".into()],
                    status: ExternalCommandStatus::Passed, exit_status: Some(0),
                }).collect(),
                toolchain_identity: "test host".into(), provenance: "disposable test".into(),
                source_inventory_before_hash: inventory.clone(), source_inventory_after_hash: inventory.clone(),
                attestation: "regression fixture".into(), limitations: vec!["fake providers".into()],
            };
            let gate = gates::create_external_verification_gate(&mut registry, &run, NewGate {
                kind: GateKind::ExternalVerification, summary: "prepared host evidence".into(),
                requested_by: Origin::ControlPlane,
                payload: GatePayload { external_verification: Some(evidence.clone()), ..GatePayload::default() },
            }, &inventory).unwrap();
            drop(registry); // durable log ends at gate.created, before acceptance
            if changed { std::fs::write(worktree.join("changed-after-gate-created"), "new bytes").unwrap(); }
            let actor = start_actor(&world, embedded_roles(), ActorOpts { reattach: true, ..ActorOpts::default() });
            if deny {
                let attempts_before = world.reopen().state().attempts.len();
                let denied = actor.handle.resolve_gate(gate.gate_id, false, Some("wrong host report".into()), common::cli_actor()).await.unwrap();
                assert!(matches!(denied, agent_control_plane::core::GateResolution::Denied { .. }));
                quiesce(&actor.handle).await;
                let current = world.reopen();
                assert_eq!(current.run(&run).unwrap().status, RunStatus::Blocked);
                assert_eq!(current.state().attempts.len(), attempts_before);
                assert!(agents_of(&current.events(&run, None, usize::MAX), RoleName::Reviewer).is_empty());
                let mut fresh = evidence;
                fresh.expected_run_seq = current.run(&run).unwrap().last_seq;
                drop(current);
                actor.stop().await;
                let actor = start_actor(&world, embedded_roles(), ActorOpts { reattach: true, ..ActorOpts::default() });
                let accepted = actor.handle.prepare_external_verification(run, fresh, common::cli_actor()).await.unwrap();
                assert!(matches!(accepted.resolution, agent_control_plane::core::GateResolution::Approved { sha: None }));
                actor.handle.status(StatusQuery { run_id: Some(run), ..StatusQuery::default() }).await.unwrap();
                let events = world.events(&run);
                assert_eq!(agents_of(&events, RoleName::Reviewer).len(), 1, "fresh evidence must start the selected reviewer");
                wait_for_status(&actor.handle, StatusQuery { run_id: Some(run), ..StatusQuery::default() },
                    "integration after replacement host evidence", |s| s.gates.iter().any(|g|
                        g.kind == GateKind::Integrate && g.status == GateStatus::Pending)).await;
                quiesce(&actor.handle).await;
                actor.stop().await;
                assert_eq!(gate_summaries(&world.events(&run), GateKind::Integrate).len(), 1);
                continue;
            }
            let result = actor.handle.resolve_gate(gate.gate_id, true, None, common::cli_actor()).await;
            quiesce(&actor.handle).await;
            actor.stop().await;
            let registry = world.reopen();
            if changed {
                assert!(result.is_err(), "stale checkout accepted after pending-gate restart: {result:?}");
                assert_eq!(registry.gate(&gate.gate_id).unwrap().status, GateStatus::Pending);
                assert!(!registry.events(&run, None, usize::MAX).iter().any(|e| matches!(&e.payload,
                    EventPayload::GateResolving { gate_id, .. } if *gate_id == gate.gate_id)));
                assert!(agents_of(&registry.events(&run, None, usize::MAX), RoleName::Reviewer).is_empty());
            } else {
                assert!(matches!(result, Ok(agent_control_plane::core::GateResolution::Approved { sha: None })));
                assert_eq!(registry.gate(&gate.gate_id).unwrap().status, GateStatus::Approved);
            }
        }
    });
}

/// Rev 25's mirror on the verify side: a report that does not echo the frozen diff's hash decides
/// nothing — one replacement verifier, then the run blocks. No reviewer, no gate, no strike, and
/// the mismatch is recorded on the attempt.
#[test]
fn a_wrong_hash_report_buys_one_replacement_verifier_and_then_the_run_blocks() {
    common::with_shared_env(|| async {
        // Pinning the variable statically poisons BOTH verifier invocations, which is the point:
        // the replacement fails the same way and the cap closes the run.
        let world = LoopWorld::new("pass", &[("ACP_FAKE_VERIFY_HASH", WRONG_VERIFY_HASH)]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let run = handle
            .delegate(delegate_builder(loop_task("T65-hash")))
            .await
            .expect("delegate")
            .run_id;
        wait_for_status(
            &handle,
            StatusQuery {
                run_id: Some(run),
                ..StatusQuery::default()
            },
            "the run blocks after two mismatched verifiers",
            |s| {
                s.runs
                    .first()
                    .is_some_and(|r| r.status == RunStatus::Blocked)
            },
        )
        .await;
        let events = world.events(&run);

        assert_eq!(agents_of(&events, RoleName::Verifier).len(), 2);
        assert!(agents_of(&events, RoleName::Reviewer).is_empty());
        assert!(gate_summaries(&events, GateKind::Integrate).is_empty());
        assert!(strike_reasons(&events).is_empty(), "the builder is not struck");
        assert!(verify_reports(&events).is_empty(), "an unbindable report is never recorded");
        assert!(
            pick(&events, |p| match p {
                EventPayload::AttemptFinished {
                    status: AttemptStatus::InvalidOutput,
                    error: Some(err),
                    ..
                } => Some(err.code),
                _ => None,
            })
            .contains(&ErrorCode::DiffHashMismatch),
            "the mismatch is recorded on the verifier attempt"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}

// ---------------------------------------------------------------------------
// Restart and compat
// ---------------------------------------------------------------------------

/// A daemon that dies with a verifier live comes back, re-attaches, and the run completes with
/// exactly one verify.report and one reviewer — the marker discipline means the branch is neither
/// lost nor doubled.
#[test]
fn a_restart_across_a_live_verify_step_completes_the_run_exactly_once() {
    common::with_shared_env(|| async {
        // The barrier makes "a verifier LIVE across the restart" deterministic rather than a
        // scheduler roll: the verifier announces its session and then holds until the test says
        // the replacement daemon is up.
        let world = LoopWorld::new("pass", &[]);
        // The barrier lives inside the state dir: self-cleaning with the TempDir, outside every
        // worktree and frozen diff. `configure_fakes` re-points the env file at it.
        let barrier_path = world.state_dir().join("verifier-barrier");
        let barrier_env = barrier_path.display().to_string();
        common::configure_fakes(
            world.repo_root(),
            "pass",
            &[("ACP_FAKE_WAIT_FILE", &barrier_env)],
        );
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let handle = actor.handle.clone();

        let run = handle
            .delegate(delegate_builder(loop_task("T65-restart")))
            .await
            .expect("delegate")
            .run_id;
        // Waiting for the verifier's SESSION, not its announcement: `agent.session` is written
        // only by the tailer over a started attempt, so the stop provably lands in the
        // reattach path — never the reissue path — and the message below stays true.
        wait_for_log(&world, &run, "the verifier's session is recorded", |events| {
            let verifiers = agents_of(events, RoleName::Verifier);
            pick(events, |p| match p {
                EventPayload::AgentSession { agent_id, .. } => Some(*agent_id),
                _ => None,
            })
            .iter()
            .any(|id| verifiers.contains(id))
        })
        .await;
        let pre_stop = world.events(&run);
        assert!(
            verify_reports(&pre_stop).is_empty(),
            "the verifier is provably still holding at the barrier when the daemon dies"
        );
        // A normal stop leaves the worker running (C3) — exactly the state a real crash leaves.
        actor.stop().await;

        let actor = start_actor(
            &world,
            embedded_roles(),
            ActorOpts {
                reattach: true,
                ..ActorOpts::default()
            },
        );
        let handle = actor.handle.clone();
        // Only now may the held verifier finish — under the replacement daemon's tailer.
        std::fs::write(&barrier_path, b"go").expect("release the barrier");
        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !gate_summaries(events, GateKind::Integrate).is_empty()
        })
        .await;

        assert_eq!(
            agents_of(&events, RoleName::Verifier).len(),
            1,
            "the restart re-attached the verifier rather than starting a second one"
        );
        assert_eq!(verify_reports(&events).len(), 1);
        assert_eq!(agents_of(&events, RoleName::Reviewer).len(), 1);

        quiesce(&handle).await;
        actor.stop().await;
    });
}

/// The compat contract T63 wrote into the loader: a roles config **without** a verifier runs the
/// Phase-1 path byte-for-byte — succeeded → review, no verifier agent, no verify.report.
#[test]
fn a_roles_config_without_a_verifier_skips_the_verify_step() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let mut cfg = (*embedded_roles()).clone();
        cfg.roles.remove(&RoleName::Verifier).expect("ours has one");
        let actor = start_actor(&world, Arc::new(cfg), ActorOpts::default());
        let handle = actor.handle.clone();

        let run = handle
            .delegate(delegate_builder(loop_task("T65-compat")))
            .await
            .expect("delegate")
            .run_id;
        let events = wait_for_log(&world, &run, "gate.created{integrate}", |events| {
            !gate_summaries(events, GateKind::Integrate).is_empty()
        })
        .await;

        assert!(agents_of(&events, RoleName::Verifier).is_empty());
        assert!(verify_reports(&events).is_empty());
        assert_eq!(agents_of(&events, RoleName::Reviewer).len(), 1);
        assert!(
            !gate_summaries(&events, GateKind::Integrate)[0].contains("Verified:"),
            "no verify line when no verify step ran"
        );

        quiesce(&handle).await;
        actor.stop().await;
    });
}
