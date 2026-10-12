//! `src/core/policy.rs` (T21): one test per `PolicyCode` this module can actually return, each
//! asserting the exact variant — `reports/03-design.md` § Test Strategy, row `core/policy.rs`.
//!
//! The eleven reachable codes are `UnknownRole`, `UnknownModel`, `DelegationNotAllowed`,
//! `DepthExceeded`, `BudgetRunExceeded`, `BudgetSpawnExceeded`, `WorktreeBusy`, `GatePending`,
//! `InvalidBaseRef`, `AgentNotResumable`, `AgentApproveNotAllowed` and `TooManyAttempts`. The argv codes
//! (`UnsafeArgv`, `SandboxMissing`, `ArgvTooLarge`, `UnsafeEnv`) belong to `assert_safe_argv`, and
//! `RunBlocked` / `ResumeTargetMissing` / `RolePromptTampered` / `GitTimeout` / `InvalidTask` are
//! raised by the actor, the roles loader, git and the MCP door respectively — no test here
//! fabricates a code this module never returns.
//!
//! Each rejection is paired with the positive control that isolates it: the same request one step
//! under the ceiling, or through the door that is allowed. A test that only ever sees `Err` cannot
//! tell "the rule fired" from "the fixture was broken".
//!
//! Every fixture registry is a `tempfile::TempDir`; nothing is written into the repo.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use agent_control_plane::core::policy::{
    check_budget, check_delegate, check_gate_resolve, check_send_message, is_valid_base_ref,
    DelegateRequest, PolicyCode, PolicyCtx, SessionSpec,
};
use agent_control_plane::core::registry::{Registry, State};
use agent_control_plane::core::team::{validate_team, Assignment, Effort, Team, ValidTeam};
use agent_control_plane::core::types::{
    Actor, AgentId, AttemptId, AttemptKind, CostSource, Defaults, EventPayload, Gate, GateId,
    GateKind, GateStatus, GatesConfig, Limits, LineageId, NewEvent, Origin, ProviderName,
    ProviderSpec, RoleName, RoleSpec, RolesConfig, RunId, SchemaName, Task, TokenUsage,
};
use tempfile::TempDir;

const SHA: &str = "1111111111111111111111111111111111111111";

/// The injected clock. No check in this module is time-dependent yet; the context still carries
/// one, so the fixture pins it rather than reading the wall clock.
fn fixed_now() -> i64 {
    1_760_000_000
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn task() -> Task {
    Task {
        id: "T21".into(),
        title: "tests/policy.rs".into(),
        description: "one test per reachable PolicyCode".into(),
        files: vec!["tests/policy.rs".into()],
        acceptance: vec!["cargo test --test policy exits 0".into()],
    }
}

fn spec(
    role: RoleName,
    models: &[&str],
    writes: bool,
    spawn_budget_usd: f64,
    allowed_delegations: &[RoleName],
) -> RoleSpec {
    RoleSpec {
        role,
        provider: if writes {
            ProviderName::Claude
        } else {
            ProviderName::Codex
        },
        models: models.iter().map(|m| (*m).to_string()).collect(),
        default_model: models.first().map_or(String::new(), |m| (*m).to_string()),
        writes,
        prompt_file: None,
        prompt_sha256: None,
        description: None,
        tools: None,
        sandbox_mode: None,
        max_turns: 40,
        spawn_budget_usd,
        result_schema: if writes {
            SchemaName::BuildResult
        } else {
            SchemaName::ReviewVerdict
        },
        allowed_delegations: allowed_delegations.to_vec(),
    }
}

/// The shipped `roles/roles.json` shape, with the numbers the design fixes: `maxDepth` 2,
/// `runBudgetUsd` 15, `spawnBudgetUsd` 2, `maxConcurrentAttempts` 2, `allowAgentApprove` false.
fn roles_cfg() -> RolesConfig {
    RolesConfig {
        version: 1,
        rates_updated: "2026-08-22".into(),
        gates: GatesConfig {
            allow_agent_approve: false,
        },
        limits: Limits {
            max_concurrent_attempts: 2,
        },
        defaults: Defaults {
            base_ref: "HEAD".into(),
            max_depth: 2,
            run_budget_usd: 15.0,
            spawn_budget_usd: 2.0,
            attempt_timeout_sec: 1800,
            await_result_max_sec: 300,
            strikes_before_replacement: 2,
            max_lineages: 2,
            denylist_globs: Vec::new(),
        },
        rates: HashMap::new(),
        providers: BTreeMap::from([
            (
                ProviderName::Claude,
                ProviderSpec {
                    models: vec!["sonnet".into(), "opus".into()],
                    efforts: Vec::new(),
                    model_efforts: BTreeMap::new(),
                },
            ),
            (
                ProviderName::Codex,
                ProviderSpec {
                    models: vec!["gpt-5.5".into()],
                    efforts: vec![Effort::Medium, Effort::High],
                    model_efforts: BTreeMap::new(),
                },
            ),
        ]),
        roles: HashMap::from([
            (
                RoleName::Lead,
                spec(
                    RoleName::Lead,
                    &[],
                    false,
                    0.0,
                    &[RoleName::Builder, RoleName::Reviewer],
                ),
            ),
            (
                RoleName::Builder,
                spec(
                    RoleName::Builder,
                    &["sonnet", "opus", "gpt-5.5"],
                    true,
                    2.0,
                    &[],
                ),
            ),
            (
                RoleName::Reviewer,
                spec(RoleName::Reviewer, &["gpt-5.5"], false, 2.0, &[]),
            ),
        ]),
    }
}

fn fresh_builder() -> DelegateRequest {
    DelegateRequest {
        run_id: None,
        role: RoleName::Builder,
        task: task(),
        model: None,
        session: SessionSpec::Fresh,
        base_ref: None,
        worktree: None,
        steps: None,
        caller_run_id: None,
    }
}

/// A registry on a scratch state dir with one run already created.
struct World {
    dir: TempDir,
    registry: Registry,
    run: RunId,
}

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut registry = Registry::open(dir.path()).expect("open registry");
        let run = RunId::new_v4();
        let created = EventPayload::RunCreated {
            execution: None,
            repo_root: dir.path().join("repo"),
            state_dir: dir.path().to_path_buf(),
            base_ref: "HEAD".into(),
            base_sha: SHA.into(),
            task: task(),
            version: 1,
            lead: Some("claude".into()),
            team_name: None,
            steps: None,
        };
        registry.append(&run, created).expect("run.created");
        Self { dir, registry, run }
    }

    fn append(&mut self, e: NewEvent) {
        self.registry.append(&self.run, e).expect("append");
    }

    /// A live writing agent in `worktree` — exactly what C5's `live_writers` scan looks for.
    fn writer(&mut self, worktree: &Path) -> AgentId {
        let agent = AgentId::new_v4();
        self.append(EventPayload::AgentCreated {
            agent_id: agent,
            role: RoleName::Builder,
            provider: ProviderName::Claude,
            model: "sonnet".into(),
            lineage_id: Some(LineageId::new_v4()),
            depth: 1,
            parent_agent_id: None,
            origin: Origin::Lead,
            writes: true,
            cwd: worktree.to_path_buf(),
            worktree: Some(worktree.to_path_buf()),
        });
        agent
    }

    /// A conversational lead has a provider session but no worker lineage or worktree.
    fn lead(&mut self) -> AgentId {
        let agent = AgentId::new_v4();
        self.append(EventPayload::AgentCreated {
            agent_id: agent,
            role: RoleName::Lead,
            provider: ProviderName::Claude,
            model: "haiku".into(),
            lineage_id: None,
            depth: 0,
            parent_agent_id: None,
            origin: Origin::Lead,
            writes: false,
            cwd: self.dir.path().join("repo"),
            worktree: None,
        });
        agent
    }

    /// A running attempt for `agent`, optionally charging `cost_usd` to the run.
    fn attempt(&mut self, agent: AgentId, cost_usd: Option<f64>) -> AttemptId {
        let attempt = AttemptId::new_v4();
        let dir = self.dir.path().join("attempts").join(attempt.to_string());
        self.append(EventPayload::AttemptStarted {
            attempt_id: attempt,
            agent_id: agent,
            attempt_kind: AttemptKind::Fresh,
            dir: dir.clone(),
            argv: vec!["claude".into(), "-p".into()],
            cwd: dir,
            pid: 4242,
            pgid: 4242,
            start_time: "Sat Aug 22 09:00:00 2026".into(),
            pre_sha: SHA.into(),
            timeout_sec: 1800,
            spawn_budget_usd: 2.0,
        });
        if let Some(cost_usd) = cost_usd {
            self.append(EventPayload::AttemptUsage {
                attempt_id: attempt,
                src_line: 7,
                cost_usd,
                tokens: TokenUsage::default(),
                source: CostSource::Provider,
            });
        }
        attempt
    }

    fn ctx<'a>(&'a self, cfg: &'a RolesConfig) -> PolicyCtx<'a> {
        PolicyCtx {
            registry: &self.registry,
            cfg,
            caller_role: RoleName::Lead,
            caller_depth: 0,
            now: fixed_now,
        }
    }
}

fn gate(kind: GateKind) -> Gate {
    Gate {
        gate_id: GateId::new_v4(),
        run_id: RunId::new_v4(),
        kind,
        status: GateStatus::Pending,
        summary: "integrate T21".into(),
        payload_path: PathBuf::from("/nonexistent/payload.json"),
        requested_by: Origin::ControlPlane,
        created_at: "2026-08-22T09:00:00Z".into(),
        resolved_at: None,
        resolved_by: None,
        approve: None,
        feedback: None,
        sha: None,
        commit: None,
    }
}

// ---------------------------------------------------------------------------
// One test per reachable PolicyCode
// ---------------------------------------------------------------------------

#[test]
fn unknown_role_when_the_config_has_no_such_role() {
    let world = World::new();
    let mut cfg = roles_cfg();
    cfg.roles.remove(&RoleName::Builder);

    let err =
        check_delegate(&fresh_builder(), &world.ctx(&cfg), None).expect_err("unconfigured role");
    assert_eq!(err.code, PolicyCode::UnknownRole);
    assert!(err.reason.contains("builder"), "{}", err.reason);

    // The same request against a config that *does* know the role is fine.
    check_delegate(&fresh_builder(), &world.ctx(&roles_cfg()), None).expect("configured role");
}

#[test]
fn unknown_model_for_anything_outside_the_roles_closed_list() {
    let world = World::new();
    let cfg = roles_cfg();

    let mut req = fresh_builder();
    req.model = Some("gpt-4o".into());
    let err = check_delegate(&req, &world.ctx(&cfg), None).expect_err("model off the list");
    assert_eq!(err.code, PolicyCode::UnknownModel);
    assert_eq!(err.detail.expect("detail")["allowed"][1], "opus");

    req.model = Some("opus".into());
    let ok = check_delegate(&req, &world.ctx(&cfg), None).expect("listed model");
    assert_eq!(ok.model, "opus");

    // A `defaultModel` the config forgot to list is not a back door either.
    let mut broken = cfg;
    broken
        .roles
        .get_mut(&RoleName::Builder)
        .expect("builder")
        .default_model = "haiku".into();
    let err =
        check_delegate(&fresh_builder(), &world.ctx(&broken), None).expect_err("unlisted default");
    assert_eq!(err.code, PolicyCode::UnknownModel);
}

/// A team that moves the builder to codex, at an effort the fixture's catalog allows.
///
/// Historical shape: pre-C1 this was minted against a non-writing builder variant because
/// `validate_team` refused a writing role on codex (`ProviderCannotWrite`). C1 retired that
/// refusal, but the fixture is kept as-is — the rules under test here are `check_delegate`'s,
/// orthogonal to the team layer's capability check either way,
/// which is exactly what a `ValidTeam` is for: proof that every value in it came out of *a* closed
/// allowlist.
fn codex_builder_team(cfg: &RolesConfig) -> ValidTeam {
    let team = Team {
        mode: None,
        version: 1,
        name: "codex builds".into(),
        lead: None,
        roles: BTreeMap::from([(
            "builder".to_string(),
            Assignment {
                provider: ProviderName::Codex,
                model: "gpt-5.5".into(),
                effort: Some(Effort::High),
            },
        )]),
    };
    let mut readonly = cfg.clone();
    readonly
        .roles
        .get_mut(&RoleName::Builder)
        .expect("builder")
        .writes = false;
    validate_team(&readonly, &team).expect("the fixture team is valid")
}

/// Rev 26: a role's `models` spans both providers so a team can move the role between them, which
/// means the role's list alone no longer says what may be spawned. Without the provider-local
/// check, `delegate{role: "builder", model: "gpt-5.5"}` would reach `claude --model gpt-5.5`.
#[test]
fn model_provider_mismatch_when_the_model_is_the_other_providers() {
    let world = World::new();
    let cfg = roles_cfg();

    // No team: the builder runs on claude, so a codex model is refused — even though the role
    // allows it, because a team could have made it spawnable.
    let mut req = fresh_builder();
    req.model = Some("gpt-5.5".into());
    let err = check_delegate(&req, &world.ctx(&cfg), None).expect_err("a codex model on claude");
    assert_eq!(err.code, PolicyCode::ModelProviderMismatch);
    assert!(
        err.reason.contains("gpt-5.5") && err.reason.contains("claude"),
        "the reason names neither the model nor the provider: {}",
        err.reason
    );
    let detail = err.detail.expect("detail");
    assert_eq!(detail["provider"], "claude");
    assert_eq!(detail["allowed"][0], "sonnet");

    // And the mirror image: with a team that moves the builder to codex, a claude model is refused.
    let team = codex_builder_team(&cfg);
    let mut req = fresh_builder();
    req.model = Some("opus".into());
    let err =
        check_delegate(&req, &world.ctx(&cfg), Some(&team)).expect_err("a claude model on codex");
    assert_eq!(err.code, PolicyCode::ModelProviderMismatch);
    assert_eq!(err.detail.expect("detail")["provider"], "codex");
}

/// The resolved spawn carries the provider the adapter must be chosen with, and the effort it must
/// be started with — `role.provider` is only the default the team overrides.
#[test]
fn the_team_decides_the_provider_and_the_effort_of_a_spawn() {
    let world = World::new();
    let cfg = roles_cfg();

    // No team: the role's own provider, and no effort. Byte-identical to pre-Rev-26 behaviour.
    let mut req = fresh_builder();
    req.model = Some("opus".into());
    let resolved = check_delegate(&req, &world.ctx(&cfg), None).expect("a claude model on claude");
    assert_eq!(resolved.provider, ProviderName::Claude);
    assert_eq!(resolved.model, "opus");
    assert_eq!(resolved.effort, None);

    // With a team, all three come from it — including the model, since the request names none.
    let team = codex_builder_team(&cfg);
    let resolved =
        check_delegate(&fresh_builder(), &world.ctx(&cfg), Some(&team)).expect("the team's choice");
    assert_eq!(resolved.provider, ProviderName::Codex);
    assert_eq!(resolved.model, "gpt-5.5");
    assert_eq!(resolved.effort, Some(Effort::High));
    assert_eq!(
        resolved.role.provider,
        ProviderName::Claude,
        "role.provider is the default the team overrode, and must not pick the adapter"
    );
}

#[test]
fn delegation_not_allowed_when_the_caller_may_not_spawn_that_role() {
    let world = World::new();
    let cfg = roles_cfg();

    // A worker calling `delegate`: `builder`'s and `reviewer`'s `allowedDelegations` are empty.
    let mut ctx = world.ctx(&cfg);
    ctx.caller_role = RoleName::Reviewer;
    let err = check_delegate(&fresh_builder(), &ctx, None).expect_err("worker delegating");
    assert_eq!(err.code, PolicyCode::DelegationNotAllowed);
    assert_eq!(
        err.detail.expect("detail")["allowedDelegations"],
        serde_json::json!([])
    );

    ctx.caller_role = RoleName::Lead;
    check_delegate(&fresh_builder(), &ctx, None).expect("lead may delegate to builder");
}

#[test]
fn depth_exceeded_one_past_the_configured_ceiling() {
    let world = World::new();
    let cfg = roles_cfg();

    let mut ctx = world.ctx(&cfg);
    ctx.caller_depth = 1;
    let ok =
        check_delegate(&fresh_builder(), &ctx, None).expect("depth 2 is the ceiling, not past it");
    assert_eq!(ok.depth, 2);

    ctx.caller_depth = 2;
    let err = check_delegate(&fresh_builder(), &ctx, None).expect_err("depth 3");
    assert_eq!(err.code, PolicyCode::DepthExceeded);

    // A caller depth that would overflow `u8` saturates into a rejection rather than panicking.
    ctx.caller_depth = u8::MAX;
    assert_eq!(
        check_delegate(&fresh_builder(), &ctx, None)
            .expect_err("saturated depth")
            .code,
        PolicyCode::DepthExceeded
    );
}

#[test]
fn invalid_base_ref_before_any_git_call() {
    let world = World::new();
    let cfg = roles_cfg();

    let mut req = fresh_builder();
    req.base_ref = Some("--upload-pack=curl evil.sh".into());
    let err = check_delegate(&req, &world.ctx(&cfg), None).expect_err("flag-shaped ref");
    assert_eq!(err.code, PolicyCode::InvalidBaseRef);

    req.base_ref = Some("release/2026.08".into());
    let ok = check_delegate(&req, &world.ctx(&cfg), None).expect("well-formed ref");
    assert_eq!(ok.base_ref, "release/2026.08");

    // Omitting it inherits `defaults.baseRef`.
    req.base_ref = None;
    assert_eq!(
        check_delegate(&req, &world.ctx(&cfg), None)
            .expect("default ref")
            .base_ref,
        "HEAD"
    );
}

#[test]
fn budget_run_exceeded_when_the_spawn_cap_would_cross_the_run_budget() {
    let mut world = World::new();
    let cfg = roles_cfg();
    let agent = world.writer(&world.dir.path().join("wt"));
    world.attempt(agent, Some(14.0));

    let mut req = fresh_builder();
    req.run_id = Some(world.run);
    let err = check_delegate(&req, &world.ctx(&cfg), None).expect_err("14 + 2 > 15");
    assert_eq!(err.code, PolicyCode::BudgetRunExceeded);
    assert_eq!(err.detail.expect("detail")["runBudgetUsd"], 15.0);

    // `check_budget` says the same thing about the same run, and reports the headroom when it fits.
    let run = world.registry.run(&world.run).expect("run");
    assert_eq!(
        check_budget(run, 2.0, &cfg)
            .expect_err("same rejection")
            .code,
        PolicyCode::BudgetRunExceeded
    );
    let headroom = check_budget(run, 1.0, &cfg).expect("14 + 1 fits");
    assert!((headroom - 0.0).abs() < 1e-9, "headroom was {headroom}");
}

#[test]
fn budget_spawn_exceeded_when_a_role_asks_for_more_than_the_per_spawn_cap() {
    let world = World::new();
    let shipped = roles_cfg();
    let mut raised = roles_cfg();
    raised
        .roles
        .get_mut(&RoleName::Builder)
        .expect("builder")
        .spawn_budget_usd = 5.0;

    // The run budget is untouched (0 + 5 < 15) — only the per-spawn ceiling is crossed.
    let err = check_delegate(&fresh_builder(), &world.ctx(&raised), None).expect_err("5 > 2");
    assert_eq!(err.code, PolicyCode::BudgetSpawnExceeded);
    assert_eq!(err.detail.expect("detail")["spawnBudgetUsd"], 2.0);

    let ok = check_delegate(&fresh_builder(), &world.ctx(&shipped), None).expect("2 == the cap");
    assert!((ok.headroom_usd - 13.0).abs() < 1e-9, "{}", ok.headroom_usd);
}

#[test]
fn too_many_attempts_when_the_run_is_at_max_concurrent_attempts() {
    let mut world = World::new();
    let cfg = roles_cfg();
    let agent = world.writer(&world.dir.path().join("wt"));

    let mut req = fresh_builder();
    req.run_id = Some(world.run);

    world.attempt(agent, None);
    check_delegate(&req, &world.ctx(&cfg), None).expect("one running attempt is under the ceiling");

    world.attempt(agent, None);
    let err = check_delegate(&req, &world.ctx(&cfg), None).expect_err("two running attempts");
    assert_eq!(err.code, PolicyCode::TooManyAttempts);
    assert!(
        err.reason.contains("maxConcurrentAttempts"),
        "{}",
        err.reason
    );
}

#[test]
fn worktree_busy_names_the_agent_already_writing_there() {
    let mut world = World::new();
    let cfg = roles_cfg();
    let worktree = world.dir.path().join("wt");
    let holder = world.writer(&worktree);

    let mut req = fresh_builder();
    req.worktree = Some(worktree.clone());
    let err = check_delegate(&req, &world.ctx(&cfg), None).expect_err("a live writer holds it");
    assert_eq!(err.code, PolicyCode::WorktreeBusy);
    assert!(err.reason.contains(&holder.to_string()), "{}", err.reason);
    assert_eq!(
        err.detail.expect("detail")["agentId"],
        holder.to_string().as_str()
    );

    // Resuming the holder is not a second writer, and an untouched worktree is free.
    req.session = SessionSpec::Resume(holder);
    check_delegate(&req, &world.ctx(&cfg), None).expect("the holder may resume itself");
    req.session = SessionSpec::Fresh;
    req.worktree = Some(world.dir.path().join("other-wt"));
    check_delegate(&req, &world.ctx(&cfg), None).expect("nobody is writing there");
}

#[test]
fn agent_not_resumable_for_an_unknown_agent_and_for_one_without_a_session() {
    let mut world = World::new();
    let cfg = roles_cfg();

    let unknown = AgentId::new_v4();
    assert_eq!(
        check_send_message(&unknown, &world.ctx(&cfg))
            .expect_err("no such agent")
            .code,
        PolicyCode::AgentNotResumable
    );

    let agent = world.writer(&world.dir.path().join("wt"));
    let attempt = world.attempt(agent, None);
    assert_eq!(
        check_send_message(&agent, &world.ctx(&cfg))
            .expect_err("no session id seen yet")
            .code,
        PolicyCode::AgentNotResumable
    );

    // `agent.session` is what makes an agent resumable.
    world.append(EventPayload::AgentSession {
        agent_id: agent,
        attempt_id: attempt,
        session_id: "sess-1".into(),
        src_line: 1,
    });
    let handle = check_send_message(&agent, &world.ctx(&cfg)).expect("resumable");
    assert_eq!(handle.agent_id, agent);

    // A spawned lead is resumable through the same follow-up policy path; lack of a worker
    // lineage is not a reason to reject its provider session.
    let lead = world.lead();
    let lead_attempt = world.attempt(lead, None);
    world.append(EventPayload::AgentSession {
        agent_id: lead,
        attempt_id: lead_attempt,
        session_id: "lead-session".into(),
        src_line: 1,
    });
    let handle = check_send_message(&lead, &world.ctx(&cfg)).expect("lead is resumable");
    assert_eq!(handle.role, RoleName::Lead);
    assert!(handle.lineage_id.is_none());

    // Budget still applies to a follow-up turn.
    world.attempt(agent, Some(14.5));
    assert_eq!(
        check_send_message(&agent, &world.ctx(&cfg))
            .expect_err("14.5 + 2 > 15")
            .code,
        PolicyCode::BudgetRunExceeded
    );
}

#[test]
fn gate_pending_tracks_only_live_integrate_gates_for_the_agents_run() {
    let mut world = World::new();
    let cfg = roles_cfg();
    let agent = world.writer(&world.dir.path().join("wt"));
    let attempt = world.attempt(agent, None);
    world.append(EventPayload::AgentSession {
        agent_id: agent,
        attempt_id: attempt,
        session_id: "sess-gated".into(),
        src_line: 1,
    });
    check_send_message(&agent, &world.ctx(&cfg)).expect("the session starts resumable");

    // A plan gate in this run, and an integrate gate in another run, own no decision window over
    // this agent. Neither may turn a valid resume into `gate_pending`.
    world.append(EventPayload::GateCreated {
        gate_id: GateId::new_v4(),
        gate_kind: GateKind::Plan,
        summary: "plan only".into(),
        payload_path: world.dir.path().join("plan.json"),
        requested_by: Origin::ControlPlane,
    });
    let other_run = RunId::new_v4();
    let other_gate = GateId::new_v4();
    world
        .registry
        .append(
            &other_run,
            EventPayload::GateCreated {
                gate_id: other_gate,
                gate_kind: GateKind::Integrate,
                summary: "another run".into(),
                payload_path: world.dir.path().join("other.json"),
                requested_by: Origin::ControlPlane,
            },
        )
        .expect("other-run gate");
    check_send_message(&agent, &world.ctx(&cfg))
        .expect("non-integrate and other-run gates do not block");

    let integrate = GateId::new_v4();
    world.append(EventPayload::GateCreated {
        gate_id: integrate,
        gate_kind: GateKind::Integrate,
        summary: "integrate this run".into(),
        payload_path: world.dir.path().join("integrate.json"),
        requested_by: Origin::ControlPlane,
    });
    let pending = check_send_message(&agent, &world.ctx(&cfg)).expect_err("pending gate blocks");
    assert_eq!(pending.code, PolicyCode::GatePending);
    assert!(
        pending.reason.contains(&integrate.to_string()),
        "{}",
        pending.reason
    );
    assert_eq!(
        pending.detail.as_ref().expect("detail")["gateId"],
        integrate.to_string()
    );
    assert_eq!(
        pending.detail.as_ref().expect("detail")["status"],
        "pending"
    );

    world.append(EventPayload::GateResolving {
        gate_id: integrate,
        approve: true,
        feedback: None,
        by: Actor::Socket {
            client_name: "cli".into(),
        },
        commit: None,
    });
    let resolving =
        check_send_message(&agent, &world.ctx(&cfg)).expect_err("resolving gate blocks");
    assert_eq!(resolving.code, PolicyCode::GatePending);
    assert_eq!(
        resolving.detail.as_ref().expect("detail")["status"],
        "resolving"
    );

    world.append(EventPayload::GateResolved {
        gate_id: integrate,
        status: GateStatus::Denied,
        sha: None,
        feedback: None,
    });
    check_send_message(&agent, &world.ctx(&cfg)).expect("a denied gate is terminal");

    // The same T52 gate boundary applies to a lineage-free lead session. This guards against a
    // role-specific follow-up exemption silently bypassing the human's integrate decision window.
    let lead = world.lead();
    let lead_attempt = world.attempt(lead, None);
    world.append(EventPayload::AgentSession {
        agent_id: lead,
        attempt_id: lead_attempt,
        session_id: "lead-gated".into(),
        src_line: 1,
    });
    let lead_gate = GateId::new_v4();
    world.append(EventPayload::GateCreated {
        gate_id: lead_gate,
        gate_kind: GateKind::Integrate,
        summary: "lead decision window".into(),
        payload_path: world.dir.path().join("lead-integrate.json"),
        requested_by: Origin::ControlPlane,
    });
    let pending = check_send_message(&lead, &world.ctx(&cfg)).expect_err("lead pending gate");
    assert_eq!(pending.code, PolicyCode::GatePending);
    assert_eq!(
        pending.detail.as_ref().expect("detail")["gateId"],
        lead_gate.to_string()
    );
    assert_eq!(
        pending.detail.as_ref().expect("detail")["status"],
        "pending"
    );
    world.append(EventPayload::GateResolving {
        gate_id: lead_gate,
        approve: false,
        feedback: Some("revise".into()),
        by: Actor::Socket {
            client_name: "acp-mac".into(),
        },
        commit: None,
    });
    let resolving = check_send_message(&lead, &world.ctx(&cfg)).expect_err("lead resolving gate");
    assert_eq!(resolving.code, PolicyCode::GatePending);
    assert_eq!(
        resolving.detail.as_ref().expect("detail")["status"],
        "resolving"
    );
    world.append(EventPayload::GateResolved {
        gate_id: lead_gate,
        status: GateStatus::Denied,
        sha: None,
        feedback: Some("revise".into()),
    });
    check_send_message(&lead, &world.ctx(&cfg)).expect("denial releases lead follow-up");

    let approved = GateId::new_v4();
    world.append(EventPayload::GateCreated {
        gate_id: approved,
        gate_kind: GateKind::Integrate,
        summary: "already integrated".into(),
        payload_path: world.dir.path().join("approved.json"),
        requested_by: Origin::ControlPlane,
    });
    world.append(EventPayload::GateResolved {
        gate_id: approved,
        status: GateStatus::Approved,
        sha: Some(SHA.into()),
        feedback: None,
    });
    check_send_message(&agent, &world.ctx(&cfg)).expect("an approved gate is terminal");

    // Gate ownership is checked before budget, so the refusal remains actionable even when both
    // conditions are true; no spawn reservation can hide the unresolved human decision.
    world.attempt(agent, Some(14.5));
    let budget_preempted = GateId::new_v4();
    world.append(EventPayload::GateCreated {
        gate_id: budget_preempted,
        gate_kind: GateKind::Integrate,
        summary: "resolve me before checking budget".into(),
        payload_path: world.dir.path().join("budget-preempted.json"),
        requested_by: Origin::ControlPlane,
    });
    assert_eq!(
        check_send_message(&agent, &world.ctx(&cfg))
            .expect_err("the gate check runs first")
            .code,
        PolicyCode::GatePending
    );
}

#[test]
fn agent_approve_not_allowed_over_mcp_for_an_integrate_gate() {
    let cfg = roles_cfg();
    let integrate = gate(GateKind::Integrate);
    let socket = Actor::Socket {
        client_name: "cli".into(),
    };

    let err = check_gate_resolve(&integrate, true, &Actor::Mcp, &cfg).expect_err("S2");
    assert_eq!(err.code, PolicyCode::AgentApproveNotAllowed);
    assert_eq!(
        err.detail.expect("detail")["gateId"],
        integrate.gate_id.to_string().as_str()
    );

    // The human door approves, the MCP door may still deny, and a non-integrate gate carries no
    // commit to authorise.
    check_gate_resolve(&integrate, true, &socket, &cfg).expect("a human may approve");
    check_gate_resolve(&integrate, false, &Actor::Mcp, &cfg).expect("the lead may deny");
    check_gate_resolve(&gate(GateKind::Escalate), true, &Actor::Mcp, &cfg)
        .expect("escalate carries no commit");

    let mut opt_in = cfg;
    opt_in.gates.allow_agent_approve = true;
    check_gate_resolve(&integrate, true, &Actor::Mcp, &opt_in).expect("opted in by config");
}

// ---------------------------------------------------------------------------
// Resolution, `is_valid_base_ref`, and the pure-function property
// ---------------------------------------------------------------------------

#[test]
fn a_delegation_that_passes_every_check_resolves_the_role_defaults() {
    let world = World::new();
    let cfg = roles_cfg();

    let resolved =
        check_delegate(&fresh_builder(), &world.ctx(&cfg), None).expect("clean delegation");
    assert_eq!(resolved.role.role, RoleName::Builder);
    assert_eq!(resolved.provider, ProviderName::Claude);
    assert_eq!(resolved.model, "sonnet");
    assert_eq!(resolved.effort, None);
    assert_eq!(resolved.depth, 1);
    assert_eq!(resolved.base_ref, "HEAD");
    assert!(resolved.writes);
    assert!((resolved.spawn_budget_usd - 2.0).abs() < 1e-9);
    assert!((resolved.headroom_usd - 13.0).abs() < 1e-9);
    assert_eq!(resolved.attempt_timeout_sec, 1800);
}

#[test]
fn is_valid_base_ref_rejects_flags_traversal_nul_empty_and_oversized_refs() {
    assert!(!is_valid_base_ref("-rf"), "a leading dash is a flag");
    assert!(!is_valid_base_ref("--upload-pack=evil"));
    assert!(
        !is_valid_base_ref("main..HEAD"),
        "`..` is a range, not a ref"
    );
    assert!(!is_valid_base_ref("../../etc/passwd"));
    assert!(!is_valid_base_ref("main\0"), "NUL");
    assert!(!is_valid_base_ref(""), "empty");
    assert!(!is_valid_base_ref(&"a".repeat(201)), "201 chars");

    // Everything outside `[A-Za-z0-9._/-]` is out, including the shell and git metacharacters a
    // ref would have to survive to be interesting.
    for bad in [
        "main branch",
        "main;rm -rf /",
        "main$(id)",
        "main`id`",
        "main\nHEAD",
        "main~1",
        "main^{}",
        "refs/heads/main:*",
        "brânche",
    ] {
        assert!(!is_valid_base_ref(bad), "{bad:?} should be rejected");
    }

    assert!(is_valid_base_ref("HEAD"));
    assert!(is_valid_base_ref("main"));
    assert!(is_valid_base_ref("feature/foo-bar_1.2"));
    assert!(is_valid_base_ref("refs/heads/main"));
    assert!(
        is_valid_base_ref(&"a".repeat(200)),
        "200 chars is the ceiling"
    );
}

#[test]
fn check_delegate_has_no_side_effects_when_it_rejects() {
    let mut world = World::new();
    let cfg = roles_cfg();
    let worktree = world.dir.path().join("wt");
    let holder = world.writer(&worktree);

    let before_state: State = world.registry.state().clone();
    let before_tree = tree(world.dir.path());
    // Guard against a vacuous comparison: the fingerprint must have caught the run's event log.
    assert!(
        before_tree.iter().any(|p| p.ends_with("events.jsonl")),
        "fingerprint missed the event log: {before_tree:?}"
    );

    // Every rejecting shape in turn, including one that names a worktree.
    let mut busy = fresh_builder();
    busy.worktree = Some(worktree.clone());
    let mut bad_ref = fresh_builder();
    bad_ref.base_ref = Some("-x".into());
    let mut bad_model = fresh_builder();
    bad_model.model = Some("gpt-4o".into());
    for req in [busy, bad_ref, bad_model] {
        check_delegate(&req, &world.ctx(&cfg), None).expect_err("rejected");
    }

    assert_eq!(
        world.registry.state(),
        &before_state,
        "a rejection appended an event or mutated the projection"
    );
    assert_eq!(
        tree(world.dir.path()),
        before_tree,
        "a rejection touched the state dir"
    );
    assert!(
        !worktree.exists(),
        "a rejection created the worktree it was asked about"
    );
    // The holder is still the only writer: policy neither adopted nor evicted an agent.
    assert_eq!(
        world
            .registry
            .live_writers(&worktree)
            .iter()
            .map(|a| a.agent_id)
            .collect::<Vec<_>>(),
        vec![holder]
    );
}

/// Every path under `root`, sorted — a cheap "nothing was written" fingerprint.
fn tree(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            out.push(path);
        }
    }
    out.sort();
    out
}


#[test]
fn cancelled_run_refuses_fresh_and_resumed_work_after_replay() {
    let cfg = roles_cfg();
    let mut world = World::new();
    let agent = world.lead();
    let attempt = world.attempt(agent, None);
    world.append(EventPayload::AgentSession { agent_id: agent, attempt_id: attempt,
        session_id: "still-known-session".into(), src_line: 1 });
    check_send_message(&agent, &world.ctx(&cfg)).unwrap();
    world.append(EventPayload::RunStatus_ { status: agent_control_plane::core::types::RunStatus::Cancelled,
        reason: Some("human cancellation".into()) });
    world.registry = Registry::open(world.dir.path()).unwrap();
    assert_eq!(check_send_message(&agent, &world.ctx(&cfg)).unwrap_err().code, PolicyCode::RunBlocked);
    let mut request = fresh_builder();
    request.run_id = Some(world.run);
    assert_eq!(check_delegate(&request, &world.ctx(&cfg), None).unwrap_err().code, PolicyCode::RunBlocked);
    request.run_id = None;
    request.session = SessionSpec::Resume(agent);
    assert_eq!(check_delegate(&request, &world.ctx(&cfg), None).unwrap_err().code, PolicyCode::RunBlocked);
    check_delegate(&fresh_builder(), &world.ctx(&cfg), None).unwrap();
}
