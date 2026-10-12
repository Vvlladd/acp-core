//! The team layer: `$ACP_STATE_DIR/team.json` and the chokepoint that turns it into the
//! provider/model/effort of the next spawn.
//! Implemented in T48 (`reports/03-design.md` § "Team layer (Revision 26)").
//!
//! The macOS app (and `acp team set`) composes the team dynamically — for every role, which
//! provider, which model, and, for codex, which reasoning effort. The daemon stays the authority:
//! the team only decides **what the next `delegate` spawns**, never argv shape, sandbox mode or
//! write rules, and every value in it is checked against the closed allowlists in
//! `roles/roles.json` before anything can reach a command line.
//!
//! That check is a type, not a convention. [`validate_team`] is the only way to obtain a
//! [`ValidTeam`], whose inner fields are private, and [`resolve_assignment`] accepts nothing else —
//! the same idiom as `CheckedPlan` in `core::policy`. An entry that failed validation, or that
//! names a role this build does not spawn, is not reachable through a `ValidTeam` at all.
//!
//! **The file is shared with the macOS app** (`apps/acp-mac/…/Team/TeamFileStore.swift`), so both
//! sides implement the same version gate: the `version` claim is read *first*, on its own, so a
//! file from a newer build reports as newer rather than as malformed even when its shape changed
//! too — and such a file is never overwritten, renamed or quarantined here. "Update the daemon" and
//! "this file is corrupt" are different remedies and only one of them is right. Quarantine is the
//! app's business (it has a human in front of it); the daemon's answer to an unreadable team file is
//! to refuse the `delegate` (`PolicyCode::TeamInvalid`) rather than silently fall back to defaults.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::core::types::{ProviderName, RoleName, RoleSpec, RolesConfig, RunMode, RunExecution, RunSteps};
use crate::providers::sandboxes_writes;

/// Version 3 requires an explicit build/plan/audit mode. Version 1 retains defaulted role
/// membership, and version 2 retains explicit membership with a required builder. Older clients
/// refuse version 3 instead of silently dropping its no-builder intent.
pub const TEAM_VERSION: u32 = 3;

/// The version at which membership became explicit — [`ValidTeam::step_enabled`] keys on it.
pub const TEAM_VERSION_EXPLICIT_MEMBERSHIP: u32 = 2;

/// The file, inside `$ACP_STATE_DIR`, that both the daemon and the app read.
pub const TEAM_FILE: &str = "team.json";

/// How much of an untrusted string from `team.json` is echoed back in an issue detail.
const MAX_ECHO_CHARS: usize = 80;

/// What the lead's assignment is called in an issue and in a log line. The lead lives in its own
/// `lead` field rather than in `roles`, so this name never collides with a role key.
const LEAD_KEY: &str = "lead";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// A codex reasoning effort. Closed set — an unattested value fails to deserialize, which is what
/// keeps `-c model_reasoning_effort=` out of reach of whoever writes the team file.
#[derive(
    Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug,
)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    /// Revision 28. Codex's `ultra` (reasoning plus automatic delegation to its own sub-agents) is
    /// deliberately not a value: acp is the delegator.
    Max,
}

impl Effort {
    /// The wire spelling — identical to what `serde` emits, and what the codex adapter puts after
    /// `model_reasoning_effort=`. Exhaustive on purpose: a new effort cannot be added without being
    /// named here.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Minimal => "minimal",
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::Xhigh => "xhigh",
            Effort::Max => "max",
        }
    }
}

impl fmt::Display for Effort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One role's provider/model/effort choice, exactly as persisted.
///
/// `deny_unknown_fields` because an assignment is small and fully specified: a key we do not know
/// here is a mistake worth reporting, not a field from the future to carry along.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assignment {
    pub provider: ProviderName,
    pub model: String,
    /// Codex only. Omitted from the encoded JSON when `None`, never written as `null` — the app
    /// writes it the same way, so a file survives a round trip through either side unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<Effort>,
}

/// `team.json` — who does what, as written by the app or `acp team set`.
///
/// Deliberately **not** `deny_unknown_fields`: within a supported version an unknown key is
/// tolerated so a slightly newer writer does not brick the daemon. A *format* change announces
/// itself by bumping `version`, which is the gate that actually refuses.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<RunMode>,
    pub version: u32,
    pub name: String,
    /// External-host provenance; also selects daemon-spawned leads in explicit v3 setup.
    /// v1/v2 spawned leads retain `roles.lead` defaults for compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead: Option<Assignment>,
    /// Keyed by role name. A `BTreeMap` so the file is diffable and re-saving an unchanged team is
    /// byte-identical, and so an unknown role name survives the load instead of being dropped.
    #[serde(default)]
    pub roles: BTreeMap<String, Assignment>,
}

// ---------------------------------------------------------------------------
// Errors and issues
// ---------------------------------------------------------------------------

/// Every way `team.json` can fail to become a [`Team`].
///
/// [`TeamError::UnsupportedVersion`] is separated from [`TeamError::Invalid`] because the remedies
/// are opposites: one file is fine and this build is old, the other file is broken.
#[derive(Debug, Error)]
pub enum TeamError {
    #[error(
        "team.json is format version {found} and this build understands version {supported} — \
         update acp rather than writing over it"
    )]
    UnsupportedVersion { found: u64, supported: u32 },
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// One thing wrong with one assignment. Reported per entry rather than as a single message so
/// `team.set` can point the app at the exact row a human has to fix.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TeamIssue {
    /// The role key from the file, or `"lead"`.
    pub role: String,
    pub code: TeamIssueCode,
    pub detail: String,
}

/// Why an assignment was rejected. Closed set, like every other code a client branches on.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TeamIssueCode {
    InvalidMode,
    UnknownProvider,
    ModelNotInProvider,
    ModelNotAllowedForRole,
    EffortUnsupported,
    EffortNotAllowed,
    /// A **writing** role assigned to a provider that cannot confine a worker to its worktree.
    ///
    /// Without a sandbox plan every spawn of that pairing is refused by `assert_safe_argv` (V4),
    /// so accepting the team here would bless a configuration whose first `delegate` always fails.
    /// The predicate lives with the adapters ([`crate::providers::sandboxes_writes`]).
    ProviderCannotWrite,
    /// A version-2 team without a `builder` entry. Membership is explicit in v2, and a team whose
    /// only writer is absent could never build anything — every delegate would be a dead end.
    BuilderRequired,
    /// A version-2 team naming a role this build does not spawn. In v2, membership decides which
    /// steps run, so a typo'd key would silently disable a step if it were merely ignored.
    UnknownRole,
}

impl TeamIssueCode {
    /// The wire spelling, identical to what `serde` emits. Exhaustive: a new code has to be named.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TeamIssueCode::InvalidMode => "invalid_mode",
            TeamIssueCode::UnknownProvider => "unknown_provider",
            TeamIssueCode::ModelNotInProvider => "model_not_in_provider",
            TeamIssueCode::ModelNotAllowedForRole => "model_not_allowed_for_role",
            TeamIssueCode::EffortUnsupported => "effort_unsupported",
            TeamIssueCode::EffortNotAllowed => "effort_not_allowed",
            TeamIssueCode::ProviderCannotWrite => "provider_cannot_write",
            TeamIssueCode::BuilderRequired => "builder_required",
            TeamIssueCode::UnknownRole => "unknown_role",
        }
    }
}

impl fmt::Display for TeamIssueCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// The chokepoint
// ---------------------------------------------------------------------------

/// A team every assignment of which has been checked against `roles/roles.json`.
///
/// The fields are private and [`validate_team`] is the only constructor, so a `ValidTeam` cannot be
/// forged: holding one *is* the proof that every provider, model and effort it can hand out came
/// out of the config's closed allowlists.
///
/// [`ValidTeam::assignment`] answers from a map built during validation rather than from the file's
/// own `roles`, so an entry that was ignored — a role name this build does not spawn — is
/// unreachable even though it is still there in [`ValidTeam::team`] for `team.get` to echo back.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidTeam {
    /// Exactly what was on disk, so `team.get` can return the human's file rather than a
    /// re-derivation of it.
    team: Team,
    /// The entries that passed, keyed by the role they resolve for. The lead lands here too.
    checked: HashMap<RoleName, Assignment>,
    /// Role keys the file names that this build does not spawn. In a **v1** team these are
    /// reported and never fatal — absence falls back to defaults, so ignoring one is harmless. In
    /// a **v2** team an unknown key is a validation issue instead ([`TeamIssueCode::UnknownRole`]):
    /// membership is the step list there, and silently ignoring a typo'd `"reviewers"` would
    /// silently disable review.
    pub ignored_roles: Vec<String>,
}

impl ValidTeam {
    /// The file this team was validated from.
    #[must_use]
    pub fn team(&self) -> &Team {
        &self.team
    }

    /// The team's name, as `run.created.teamName` records it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.team.name
    }

    /// The lead's assignment, if the file names one.
    #[must_use]
    pub fn lead(&self) -> Option<&Assignment> {
        self.checked.get(&RoleName::Lead)
    }

    /// This team's checked choice for `role`, or `None` when it does not name one.
    #[must_use]
    pub fn assignment(&self, role: RoleName) -> Option<&Assignment> {
        self.checked.get(&role)
    }

    /// Whether this team runs `role`'s step at all (B3 role subsets).
    ///
    /// A v1 team enables everything — absence only ever meant "use the default assignment". From
    /// [`TEAM_VERSION_EXPLICIT_MEMBERSHIP`] on, membership is the switch: an absent spawnable role
    /// is a step the human chose not to run. The builder is mandatory ([`validate_team`] refuses a
    /// v2 team without one) and the lead is not a step, so both always answer `true`. Callers
    /// **capture** this answer when a run is created rather than re-asking later, so a `team.json`
    /// edit mid-run cannot change a running run's shape.
    #[must_use]
    pub fn step_enabled(&self, role: RoleName) -> bool {
        if role == RoleName::Security && self.team.version < 3 { return false; }
        if self.team.version < TEAM_VERSION_EXPLICIT_MEMBERSHIP {
            return true;
        }
        role == RoleName::Lead || self.checked.contains_key(&role)
    }

    pub fn mode(&self) -> RunMode {
        self.team.mode.unwrap_or_default()
    }

    /// Consumes the wrapper, yielding the file it was validated from.
    #[must_use]
    pub fn into_team(self) -> Team {
        self.team
    }
}

/// Checks every assignment in `team` against `cfg`'s closed allowlists.
///
/// The rules (design, § Team layer):
///
/// - the provider must be one the config carries;
/// - the model must be in `providers[provider].models` **and** in `roles[role].models` — the
///   provider catalog says what exists, the role's list says what that role may be given;
/// - `effort` may be present only when the provider takes efforts, and then must be one of them;
/// - the team's **lead** assignment remains informational in v1 and is checked against the
///   provider catalog only; app-spawned leads use `roles.lead` defaults instead;
/// - a role key this build does not spawn — including `"lead"`, which belongs in the `lead` field —
///   is *ignored with a warning* in a v1 team; in a v2 team it is an [`TeamIssueCode::UnknownRole`]
///   issue, because membership decides which steps run there;
/// - a v2 team must name a `builder` ([`TeamIssueCode::BuilderRequired`]): membership is explicit
///   and the one writer cannot be opted out.
///
/// Every failing entry is reported, not just the first: a human fixing a team file should see the
/// whole list.
///
/// # Errors
///
/// The issues, one per failed check, when any assignment is not allowed.
pub fn validate_team(cfg: &RolesConfig, team: &Team) -> Result<ValidTeam, Vec<TeamIssue>> {
    let mut issues = Vec::new();
    let mut checked = HashMap::new();
    let mut ignored_roles = Vec::new();

    let mode = team.mode.unwrap_or_default();
    let has_builder = team.roles.contains_key("builder");
    if (team.version < 3 && team.mode.is_some()) || (team.version == 3 && team.mode.is_none()) {
        issues.push(TeamIssue { role: "mode".into(), code: TeamIssueCode::InvalidMode,
            detail: "mode is required in version 3 and must be absent in older teams".into() });
    }
    if team.version >= 2 && mode == RunMode::Build && !has_builder {
        issues.push(TeamIssue { role: "builder".into(), code: TeamIssueCode::BuilderRequired,
            detail: "build mode requires a builder entry".into() });
    }
    if (mode == RunMode::Plan && !team.roles.is_empty())
        || (mode == RunMode::Audit && (has_builder || team.roles.is_empty())) {
        issues.push(TeamIssue { role: "mode".into(), code: TeamIssueCode::InvalidMode,
            detail: "planning has no workers; audit has checks and no builder".into() });
    }

    if let Some(lead) = &team.lead {
        // Older files recorded only external-host provenance. v3 also selects spawned leads.
        let spec = if team.version >= 3 { cfg.roles.get(&RoleName::Lead) } else { None };
        if team.version >= 3 && spec.is_none() {
            issues.push(TeamIssue { role: LEAD_KEY.into(), code: TeamIssueCode::UnknownRole,
                detail: "this daemon has no configured lead role".into() });
        }
        check_assignment(cfg, LEAD_KEY, lead, spec, &mut issues);
        checked.insert(RoleName::Lead, lead.clone());
    }

    for (key, assignment) in &team.roles {
        let Some(spec) = spawnable_role(key).filter(|role| *role != RoleName::Security || team.version >= 3).and_then(|role| cfg.roles.get(&role)) else {
            // v1: harmless, absence falls back to defaults. v2: membership IS the step list, so
            // an unknown key must refuse rather than silently disable whatever it was meant to be.
            if team.version >= TEAM_VERSION_EXPLICIT_MEMBERSHIP {
                issues.push(TeamIssue {
                    role: key.clone(),
                    code: TeamIssueCode::UnknownRole,
                    detail: format!(
                        "`{}` is not a spawnable role in this daemon's catalog; in a version-2 \
                         team every key decides a step",
                        echo(key)
                    ),
                });
            } else {
                tracing::warn!(
                    role = %echo(key),
                    "team.json names a role this build does not spawn; ignoring it"
                );
                ignored_roles.push(key.clone());
            }
            continue;
        };
        check_assignment(cfg, key, assignment, Some(spec), &mut issues);
        checked.insert(spec.role, assignment.clone());
    }

    if issues.is_empty() {
        Ok(ValidTeam {
            team: team.clone(),
            checked,
            ignored_roles,
        })
    } else {
        Err(issues)
    }
}

/// Appends an issue for each rule `assignment` breaks. Only legacy informational lead choices
/// omit the per-role model allowlist.
fn check_assignment(
    cfg: &RolesConfig,
    role_key: &str,
    assignment: &Assignment,
    spec: Option<&RoleSpec>,
    issues: &mut Vec<TeamIssue>,
) {
    let issue = |code, detail| TeamIssue {
        role: role_key.to_owned(),
        code,
        detail,
    };

    let Some(provider) = cfg.providers.get(&assignment.provider) else {
        // Nothing else about the entry can be judged without a catalog to judge it against.
        issues.push(issue(
            TeamIssueCode::UnknownProvider,
            format!(
                "`{}` is not a provider in roles.json",
                provider_str(assignment.provider)
            ),
        ));
        return;
    };

    if !contains(&provider.models, &assignment.model) {
        issues.push(issue(
            TeamIssueCode::ModelNotInProvider,
            format!(
                "provider `{}` has no model `{}` (it offers {})",
                provider_str(assignment.provider),
                echo(&assignment.model),
                list(&provider.models)
            ),
        ));
    }

    if let Some(spec) = spec {
        // A sandboxed role (a writer, or the B1 verifier) needs a provider that can be confined
        // to the worktree. The spawn chokepoint enforces it (V4); refusing here is what stops a
        // team from being *saved* in a shape whose every spawn would be rejected.
        if spec.requires_sandbox() && !sandboxes_writes(assignment.provider) {
            issues.push(issue(
                TeamIssueCode::ProviderCannotWrite,
                format!(
                    "role `{role_key}` needs the provider's kernel sandbox, and provider `{}` has \
                     none to confine it to the worktree; every spawn of this pairing would be \
                     refused",
                    provider_str(assignment.provider)
                ),
            ));
        }
        if !contains(&spec.models, &assignment.model) {
            issues.push(issue(
                TeamIssueCode::ModelNotAllowedForRole,
                format!(
                    "role `{}` may not use model `{}` (it allows {})",
                    role_key,
                    echo(&assignment.model),
                    list(&spec.models)
                ),
            ));
        }
    }

    if let Some(effort) = assignment.effort {
        if provider.efforts.is_empty() {
            issues.push(issue(
                TeamIssueCode::EffortUnsupported,
                format!(
                    "provider `{}` takes no reasoning effort, but `{effort}` was set",
                    provider_str(assignment.provider)
                ),
            ));
        } else if !provider.efforts.contains(&effort) {
            issues.push(issue(
                TeamIssueCode::EffortNotAllowed,
                format!(
                    "provider `{}` does not accept effort `{effort}` (it accepts {})",
                    provider_str(assignment.provider),
                    list(provider.efforts.iter().map(|e| e.as_str()))
                ),
            ));
        } else if !provider.efforts_for(&assignment.model).contains(&effort) {
            // Revision 28: a model may narrow its provider's list. The model is named because
            // "codex does not accept `max`" would be false for the models that do take it.
            issues.push(issue(
                TeamIssueCode::EffortNotAllowed,
                format!(
                    "model `{}` does not accept effort `{effort}` (it accepts {})",
                    echo(&assignment.model),
                    list(
                        provider
                            .efforts_for(&assignment.model)
                            .iter()
                            .map(|e| e.as_str())
                    )
                ),
            ));
        }
    }
}

/// What `role` should be spawned with: the team's checked choice when it names one, otherwise the
/// role's own defaults from `roles.json`.
///
/// New runs capture this result. Their later workers and recovery use that persisted selection;
/// editing `team.json` affects subsequent runs. Legacy runs without an execution record retain
/// their original fallback behavior.
///
/// A role the config does not carry cannot be spawned at all (`check_delegate` rejects it with
/// `PolicyCode::UnknownRole` long before this is reached); it resolves to an empty model here so
/// that a caller which skipped that check fails at the next one rather than silently getting a
/// default.
#[must_use]
pub fn resolve_assignment(
    cfg: &RolesConfig,
    team: Option<&ValidTeam>,
    role: RoleName,
) -> Assignment {
    if let Some(assignment) = team.and_then(|team| team.assignment(role)) {
        return assignment.clone();
    }
    match cfg.roles.get(&role) {
        Some(spec) => Assignment {
            provider: spec.provider,
            model: spec.default_model.clone(),
            effort: None,
        },
        None => {
            tracing::warn!(role = %role_key(role), "no such role in roles.json");
            Assignment {
                provider: ProviderName::Claude,
                model: String::new(),
                effort: None,
            }
        }
    }
}

/// Resolve the complete run configuration once, including fallback assignments for explicit
/// per-item check overrides. `steps` records membership separately; recording a fallback does not
/// enable it. Execution intent is never inferred from omissions in version-1/2 teams.
pub fn capture_execution(cfg: &RolesConfig, team: Option<&ValidTeam>) -> RunExecution {
    let mut assignments = BTreeMap::new();
    for role in [RoleName::Builder, RoleName::Verifier, RoleName::Reviewer, RoleName::Security] {
        if cfg.roles.contains_key(&role) {
            assignments.insert(role_key(role).to_string(), resolve_assignment(cfg, team, role));
        }
    }
    RunExecution { authorized_audit_selection: None, audit_selection: None, version: 1, mode: team.map_or(RunMode::Build, ValidTeam::mode), assignments,
        steps: team.map(|t| RunSteps { security: t.step_enabled(RoleName::Security), verify: t.step_enabled(RoleName::Verifier),
            review: t.step_enabled(RoleName::Reviewer) }).unwrap_or_default() }
}

/// Revalidate a persisted selection against the closed runtime catalog, without consulting the
/// current team file. Disabled assignments remain recorded for explicit per-plan item overrides.
pub fn from_execution(cfg: &RolesConfig, execution: &RunExecution) -> Result<ValidTeam, Vec<TeamIssue>> {
    if execution.version != 1 {
        return Err(vec![TeamIssue { role: "execution".into(), code: TeamIssueCode::InvalidMode,
            detail: "this run configuration version is unsupported".into() }]);
    }
    let mut roles = execution.assignments.clone();
    let lead = roles.remove(LEAD_KEY);
    if execution.mode != RunMode::Build { roles.remove("builder"); }
    if !execution.steps.verify || execution.mode == RunMode::Plan { roles.remove("verifier"); }
    if !execution.steps.review || execution.mode == RunMode::Plan { roles.remove("reviewer"); }
    if !execution.steps.security || execution.mode == RunMode::Plan { roles.remove("security"); }
    validate_team(cfg, &Team { mode: Some(execution.mode), version: 3,
        name: "Recorded task team".into(), lead, roles })
}

// ---------------------------------------------------------------------------
// The catalog (`roles.list`)
// ---------------------------------------------------------------------------

/// The `roles.list` result: everything a client needs to compose a team.
///
/// The wire shape is the app's `RoleCatalog` (`apps/acp-mac/…/Team/RoleCatalog.swift`), which is
/// also the shape of its bundled `roles.fallback.json`. Ids and nothing else: display names and
/// prices are the client's business.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RolesListResult {
    /// Version 1 supports actor-checked expectedTeam and explicit auditSelection on lead.start.
    /// Missing on older daemons; clients must check before mutating a confirmed setup.
    #[serde(default)]
    pub human_setup_version: u32,
    /// Separate from worker membership; absent on older daemons or catalogs without a lead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead: Option<RolesListRole>,
    pub roles: Vec<RolesListRole>,
    pub providers: BTreeMap<ProviderName, RolesListProvider>,
}

/// One spawnable role, with the allowlist a client's model picker is bounded by.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RolesListRole {
    pub name: String,
    pub provider: ProviderName,
    pub models: Vec<String>,
    pub default_model: String,
    pub writes: bool,
    pub description: Option<String>,
}

/// One provider's catalog entry, plus whether its CLI was found on `PATH`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RolesListProvider {
    pub models: Vec<String>,
    pub efforts: Vec<Effort>,
    /// Revision 28: per-model narrowing of `efforts`, sent only when at least one model narrows —
    /// absent for claude and from older daemons, so a client that never heard of it keeps decoding.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub model_efforts: BTreeMap<String, Vec<Effort>>,
    pub available: bool,
}

impl RolesListProvider {
    /// The efforts `model` may be given — its own list when the daemon narrowed it, else the
    /// provider's — for a client (`acp start`) that reads the wire shape rather than the config.
    #[must_use]
    pub fn efforts_for(&self, model: &str) -> &[Effort] {
        self.model_efforts
            .get(model)
            .map_or(self.efforts.as_slice(), Vec::as_slice)
    }
}

/// Projects `cfg` into the catalog a client picks a team from.
///
/// `available` is the `PATH` probe `doctor` already does, keyed by provider. A provider the caller
/// did not probe is reported **unavailable**: the field is a claim about this machine, and the
/// honest answer to "was it found?" when nobody looked is no.
///
/// The lead is excluded from `roles`: the team editor's lead field remains informational in v1,
/// while app-spawned leads use `roles.lead` defaults. Roles are sorted by name so two calls with
/// the same config return the same document.
#[must_use]
pub fn roles_list(cfg: &RolesConfig, available: &BTreeMap<ProviderName, bool>) -> RolesListResult {
    let mut roles: Vec<RolesListRole> = cfg
        .roles
        .iter()
        .filter(|(role, _)| **role != RoleName::Lead)
        .map(|(role, spec)| RolesListRole {
            name: role_key(*role).to_owned(),
            provider: spec.provider,
            models: spec.models.clone(),
            default_model: spec.default_model.clone(),
            writes: spec.writes,
            description: spec.description.clone(),
        })
        .collect();
    roles.sort_by(|a, b| a.name.cmp(&b.name));

    let providers = cfg
        .providers
        .iter()
        .map(|(name, spec)| {
            (
                *name,
                RolesListProvider {
                    models: spec.models.clone(),
                    efforts: spec.efforts.clone(),
                    model_efforts: spec.model_efforts.clone(),
                    available: available.get(name).copied().unwrap_or(false),
                },
            )
        })
        .collect();

    let lead = cfg.roles.get(&RoleName::Lead).map(|spec| RolesListRole {
        name: "lead".into(), provider: spec.provider, models: spec.models.clone(),
        default_model: spec.default_model.clone(), writes: false, description: spec.description.clone(),
    });
    RolesListResult { human_setup_version: 1, lead, roles, providers }
}

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

/// `<state_dir>/team.json`.
#[must_use]
pub fn team_path(state_dir: &Path) -> PathBuf {
    state_dir.join(TEAM_FILE)
}

/// The persisted team, or `None` when there is no file yet.
///
/// Read at `delegate` time rather than cached at startup, so a `team.set` or a direct write from
/// the app takes effect on the next spawn.
///
/// The `version` claim is decoded on its own first, so a file from a newer build reports as
/// [`TeamError::UnsupportedVersion`] even when its shape changed too. Nothing here writes, renames
/// or deletes: a file that cannot be read is left exactly as it is, byte for byte.
///
/// # Errors
///
/// [`TeamError::UnsupportedVersion`] for a newer format, [`TeamError::Invalid`] for a file that is
/// not a supported team at all, [`TeamError::Io`] for a file that cannot be read at all.
pub fn load_team(state_dir: &Path) -> Result<Option<Team>, TeamError> {
    let path = team_path(state_dir);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(io_at(&path, &err)),
    };

    if let Some(found) = version_claim(&bytes) {
        if found > u64::from(TEAM_VERSION) {
            return Err(TeamError::UnsupportedVersion {
                found,
                supported: TEAM_VERSION,
            });
        }
    }

    let team: Team = serde_json::from_slice(&bytes)
        .map_err(|err| TeamError::Invalid(format!("{}: {err}", path.display())))?;
    Ok(Some(team))
}

/// Writes `team` atomically, 0600, creating `state_dir` 0700 if it is missing.
///
/// The payload lands in a temporary file **in the same directory** and is then renamed over the
/// target, so a concurrent reader sees either the old file or the new one and never a half-written
/// one.
///
/// What is already there is re-read immediately before the rename, and there are three outcomes:
/// missing or readable → write; a **newer** version → refuse ([`TeamError::UnsupportedVersion`]);
/// present but undecodable → refuse ([`TeamError::Invalid`]). Refusing at [`load_team`] alone is
/// not enough — a team read while the file was v1 is stale the moment a newer writer replaces it,
/// and those bytes are the human's. This mirrors the app's `TeamFileStore.save`, down to the
/// distinction between the two refusals.
///
/// **A check-then-write, not a lock.** It closes the stale-draft window (minutes, while a human
/// edits), not the microseconds between the check and the rename; the same accepted limitation the
/// app records.
///
/// # Errors
///
/// [`TeamError::UnsupportedVersion`] when `team` — or the file being replaced — claims a version
/// this build cannot write, [`TeamError::Invalid`] when a file is in the way that cannot be read as
/// a team, [`TeamError::Io`] for any filesystem failure.
pub fn save_team(state_dir: &Path, team: &Team) -> Result<(), TeamError> {
    if team.version > TEAM_VERSION {
        return Err(TeamError::UnsupportedVersion {
            found: u64::from(team.version),
            supported: TEAM_VERSION,
        });
    }

    let path = team_path(state_dir);
    let mut json = serde_json::to_string_pretty(team)
        .map_err(|err| TeamError::Invalid(format!("{}: {err}", path.display())))?;
    json.push('\n');

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state_dir)
        .map_err(|err| io_at(state_dir, &err))?;

    let temp = state_dir.join(format!("{TEAM_FILE}.tmp-{}", Uuid::new_v4()));
    write_0600(&temp, json.as_bytes()).map_err(|err| io_at(&temp, &err))?;

    // As late as possible, so the window between the check and the rename is as small as a
    // check-then-write can make it.
    let outcome = match existing_file(&path) {
        ExistingFile::Absent | ExistingFile::Readable => {
            fs::rename(&temp, &path).map_err(|err| io_at(&path, &err))
        }
        ExistingFile::Newer(found) => Err(TeamError::UnsupportedVersion {
            found,
            supported: TEAM_VERSION,
        }),
        ExistingFile::Unreadable => Err(TeamError::Invalid(format!(
            "{} exists but cannot be read as a team file — move it aside before saving",
            path.display()
        ))),
    };
    if outcome.is_err() {
        // The temporary file is the only thing that could be left behind, and it is ours.
        let _ = fs::remove_file(&temp);
    }
    outcome
}

/// Creates `path` 0600 — failing if it already exists — and writes `bytes` durably.
///
/// `create_new` matters: the name carries a v4 uuid, so anything already sitting there was planted,
/// and following it would be writing through someone else's file.
fn write_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// What is sitting at `path` right now, from the point of view of something about to replace it.
///
/// The version claim is settled first, so a newer file reports as newer even when this build also
/// cannot decode its shape. Everything else has to decode as a [`Team`] to count as replaceable: a
/// read error other than "no such file", an empty file and a hand-broken one are all unreadable,
/// which fails closed toward keeping the bytes.
fn existing_file(path: &Path) -> ExistingFile {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return ExistingFile::Absent,
        Err(_) => return ExistingFile::Unreadable,
    };
    if let Some(found) = version_claim(&bytes) {
        if found > u64::from(TEAM_VERSION) {
            return ExistingFile::Newer(found);
        }
    }
    match serde_json::from_slice::<Team>(&bytes) {
        Ok(_) => ExistingFile::Readable,
        Err(_) => ExistingFile::Unreadable,
    }
}

enum ExistingFile {
    Absent,
    Readable,
    Newer(u64),
    Unreadable,
}

/// Just enough of a file to know which format it claims to be.
///
/// `version` is optional because a file that omits it makes no claim, and that is the full decode's
/// business rather than this one's. Something that is not JSON at all fails here too and falls
/// through to the full decode, which reports the real parse error.
#[derive(Deserialize)]
struct VersionEnvelope {
    version: Option<u64>,
}

fn version_claim(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<VersionEnvelope>(bytes)
        .ok()
        .and_then(|envelope| envelope.version)
}

/// Names the file in an I/O error. The kind — which is what callers branch on — is preserved.
fn io_at(path: &Path, err: &io::Error) -> TeamError {
    TeamError::Io(io::Error::new(
        err.kind(),
        format!("{}: {err}", path.display()),
    ))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// The wire spelling of a role name, and the key it has in `team.json`. Exhaustive, so a new role
/// cannot be added without deciding how it is named here.
fn role_key(role: RoleName) -> &'static str {
    match role {
        RoleName::Lead => "lead",
        RoleName::Builder => "builder",
        RoleName::Reviewer => "reviewer",
        RoleName::Verifier => "verifier",
        RoleName::Security => "security",
    }
}

/// The worker role a `team.json.roles` key names.
///
/// `"lead"` is deliberately not one: the lead is carried by the file's own `lead` field, it is
/// team that is refused.
/// In a v1 team an unrecognised key (including `"lead"`) is ignored; from v2 on it is an
/// [`TeamIssueCode::UnknownRole`] refusal, because membership decides which steps run.
fn spawnable_role(key: &str) -> Option<RoleName> {
    match key {
        "builder" => Some(RoleName::Builder),
        "reviewer" => Some(RoleName::Reviewer),
        // B1: team-assignable (who verifies is a team choice) while staying outside
        // `DelegatableRole` on both doors — only the control plane starts a verifier.
        "verifier" => Some(RoleName::Verifier),
        "security" => Some(RoleName::Security),
        _ => None,
    }
}

/// The wire spelling of a provider name. `pub(crate)` because `core::policy` names the provider in
/// its `model_provider_mismatch` rejection and there is no reason for two copies of this match.
pub(crate) fn provider_str(provider: ProviderName) -> &'static str {
    match provider {
        ProviderName::Claude => "claude",
        ProviderName::Codex => "codex",
    }
}

fn contains(haystack: &[String], needle: &str) -> bool {
    haystack.iter().any(|candidate| candidate == needle)
}

/// Renders an allowlist for an issue detail: `none` when it is empty, so the sentence still reads.
fn list<I: IntoIterator<Item = S>, S: AsRef<str>>(items: I) -> String {
    let rendered = items
        .into_iter()
        .map(|item| format!("`{}`", item.as_ref()))
        .collect::<Vec<_>>()
        .join(", ");
    if rendered.is_empty() {
        "none".to_owned()
    } else {
        rendered
    }
}

/// Truncates a string from `team.json` on a char boundary before it is echoed into an issue or a
/// log line.
fn echo(s: &str) -> String {
    match s.char_indices().nth(MAX_ECHO_CHARS) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    use serde_json::{json, Value};
    use tempfile::TempDir;

    use crate::roles::loader::load_roles;

    fn cfg() -> std::sync::Arc<RolesConfig> {
        load_roles(None).expect("embedded roles config")
    }

    /// B1 (T63) → C1 (T67): originally this asserted the codex-verifier REFUSAL; T67's
    /// `sandboxes_writes` flip retired that half exactly as planned, and both providers now
    /// validate. The historical refusal window is pinned by the git history, not by a test
    /// against an unreachable state.
    #[test]
    fn a_verifier_team_entry_validates_like_any_sandboxed_role() {
        let cfg = cfg();
        let refused = validate_team(
            &cfg,
            &team_json(json!({
                "version": 1, "name": "t",
                "roles": { "verifier": { "provider": "codex", "model": "gpt-5.5" } }
            })),
        );
        // C1 flipped `sandboxes_writes(Codex)`: the once-refused pairing now validates.
        let team = refused.expect("a codex verifier is a legal assignment since C1");
        assert!(team.ignored_roles.is_empty());

        let accepted = validate_team(
            &cfg,
            &team_json(json!({
                "version": 1, "name": "t",
                "roles": { "verifier": { "provider": "claude", "model": "haiku" } }
            })),
        )
        .expect("a claude verifier is a valid team");
        assert!(accepted.ignored_roles.is_empty(), "verifier is not ignored");
    }

    /// B1 (T62) → C1 (T67): originally the pre-C1 refusal proof (codex verifier refused like a
    /// codex builder while `sandboxes_writes(Codex)` was false). The flip retired the refusal;
    /// what this still pins is that the capability check keys on `requires_sandbox` and treats
    /// both providers uniformly — the same predicate, both directions green.
    #[test]
    fn a_codex_verifier_is_refused_while_codex_cannot_sandbox() {
        let base = cfg();
        let verifier = RoleSpec {
            role: RoleName::Verifier,
            provider: ProviderName::Claude,
            models: vec!["haiku".into(), "gpt-5.5".into()],
            default_model: "haiku".into(),
            writes: false,
            prompt_file: None,
            prompt_sha256: None,
            description: None,
            tools: None,
            sandbox_mode: None,
            max_turns: 16,
            spawn_budget_usd: 2.0,
            result_schema: crate::core::types::SchemaName::VerifyReport,
            allowed_delegations: Vec::new(),
        };
        let assignment = Assignment {
            provider: ProviderName::Codex,
            model: "gpt-5.5".into(),
            effort: None,
        };
        let mut issues = Vec::new();
        check_assignment(&base, "verifier", &assignment, Some(&verifier), &mut issues);
        // C1: codex sandboxes writes now, so the sandboxed-role check passes for it too.
        assert!(
            !issues
                .iter()
                .any(|i| i.code == TeamIssueCode::ProviderCannotWrite),
            "since C1 a codex verifier is confinable: {issues:?}"
        );
        // The same spec on claude is fine — the refusal is about the provider, not the role.
        let claude = Assignment {
            provider: ProviderName::Claude,
            model: "haiku".into(),
            effort: None,
        };
        let mut ok = Vec::new();
        check_assignment(&base, "verifier", &claude, Some(&verifier), &mut ok);
        assert!(
            !ok.iter()
                .any(|i| i.code == TeamIssueCode::ProviderCannotWrite),
            "claude sandboxes writes; the verifier assignment must not be refused: {ok:?}"
        );
    }

    fn team_json(value: Value) -> Team {
        serde_json::from_value(value).expect("team")
    }

    /// The example from the app brief § 3, which the daemon must accept unchanged.
    fn brief_team() -> Value {
        json!({
            "version": 1,
            "name": "Opus builds, Codex reviews",
            "lead": { "provider": "claude", "model": "opus" },
            "roles": {
                "builder": { "provider": "claude", "model": "sonnet" },
                "reviewer": { "provider": "codex", "model": "gpt-5.5", "effort": "high" }
            }
        })
    }

    #[test]
    fn the_brief_example_validates_and_resolves() {
        let cfg = cfg();
        let team = validate_team(&cfg, &team_json(brief_team())).expect("valid");

        assert!(team.ignored_roles.is_empty());
        assert_eq!(team.name(), "Opus builds, Codex reviews");
        assert_eq!(team.lead().map(|a| a.model.as_str()), Some("opus"));

        let builder = resolve_assignment(&cfg, Some(&team), RoleName::Builder);
        assert_eq!(builder.provider, ProviderName::Claude);
        assert_eq!(builder.model, "sonnet");
        assert_eq!(builder.effort, None);

        let reviewer = resolve_assignment(&cfg, Some(&team), RoleName::Reviewer);
        assert_eq!(reviewer.provider, ProviderName::Codex);
        assert_eq!(reviewer.effort, Some(Effort::High));
    }

    #[test]
    fn no_team_resolves_to_the_role_defaults() {
        let cfg = cfg();

        let builder = resolve_assignment(&cfg, None, RoleName::Builder);
        assert_eq!(builder.provider, ProviderName::Claude);
        assert_eq!(builder.model, "sonnet");
        assert_eq!(builder.effort, None);

        let reviewer = resolve_assignment(&cfg, None, RoleName::Reviewer);
        assert_eq!(reviewer.provider, ProviderName::Codex);
        assert_eq!(reviewer.model, "gpt-5.5");
    }

    /// A team that names only one role leaves the other on its default.
    #[test]
    fn a_partial_team_falls_back_per_role() {
        let cfg = cfg();
        // Only the builder is named — and with a model that is *not* its default, so what is
        // resolved for it can only have come from the team. Its provider stays claude, because a
        // writing role on a provider with no sandbox is refused outright (`ProviderCannotWrite`).
        let team = validate_team(
            &cfg,
            &team_json(json!({
                "version": 1,
                "name": "half",
                "roles": { "builder": { "provider": "claude", "model": "opus" } }
            })),
        )
        .expect("valid");

        assert_eq!(
            resolve_assignment(&cfg, Some(&team), RoleName::Builder).provider,
            ProviderName::Claude
        );
        assert_eq!(
            resolve_assignment(&cfg, Some(&team), RoleName::Builder).model,
            "opus",
            "the team's choice, not the role default"
        );
        assert_eq!(
            resolve_assignment(&cfg, Some(&team), RoleName::Reviewer).model,
            "gpt-5.5"
        );
        assert!(resolve_assignment(&cfg, Some(&team), RoleName::Reviewer)
            .effort
            .is_none());
    }

    fn issue_codes(value: Value) -> Vec<TeamIssueCode> {
        let cfg = cfg();
        let issues = validate_team(&cfg, &team_json(value)).expect_err("invalid");
        issues.into_iter().map(|issue| issue.code).collect()
    }

    #[test]
    fn a_model_outside_the_provider_catalog_is_rejected() {
        assert_eq!(
            issue_codes(json!({
                "version": 1, "name": "t",
                "roles": { "builder": { "provider": "claude", "model": "gpt-9" } }
            })),
            vec![
                TeamIssueCode::ModelNotInProvider,
                TeamIssueCode::ModelNotAllowedForRole
            ]
        );
    }

    #[test]
    fn an_effort_on_claude_is_rejected() {
        assert_eq!(
            issue_codes(json!({
                "version": 1, "name": "t",
                "roles": { "builder": { "provider": "claude", "model": "sonnet", "effort": "high" } }
            })),
            vec![TeamIssueCode::EffortUnsupported]
        );
    }

    /// The lead is checked against the provider catalog and nothing else — `roles.lead` carries no
    /// model list, so a lead model that no role may be spawned with is still fine.
    #[test]
    fn the_lead_is_checked_against_providers_only() {
        let cfg = cfg();
        let ok = validate_team(
            &cfg,
            &team_json(json!({
                "version": 1, "name": "t",
                "lead": { "provider": "claude", "model": "haiku" },
                "roles": {}
            })),
        )
        .expect("valid");
        assert_eq!(ok.lead().map(|a| a.model.as_str()), Some("haiku"));

        assert_eq!(
            issue_codes(json!({
                "version": 1, "name": "t",
                "lead": { "provider": "claude", "model": "gpt-5.5" },
                "roles": {}
            })),
            vec![TeamIssueCode::ModelNotInProvider]
        );
    }

    #[test]
    fn an_unknown_role_is_ignored_not_fatal() {
        let cfg = cfg();
        let team = validate_team(
            &cfg,
            &team_json(json!({
                "version": 1, "name": "t",
                "roles": {
                    "builder": { "provider": "claude", "model": "sonnet" },
                    "nonesuch": { "provider": "claude", "model": "sonnet" },
                    "lead": { "provider": "codex", "model": "gpt-5.5" }
                }
            })),
        )
        .expect("valid");

        assert_eq!(team.ignored_roles, vec!["lead", "nonesuch"]);
        // An ignored entry is unreachable: the lead here came from `roles`, not from `lead`.
        assert!(team.lead().is_none());
        assert_eq!(
            resolve_assignment(&cfg, Some(&team), RoleName::Builder).model,
            "sonnet"
        );
    }

    #[test]
    fn an_unknown_effort_does_not_deserialize() {
        let err = serde_json::from_value::<Assignment>(json!({
            "provider": "codex", "model": "gpt-5.5", "effort": "turbo"
        }))
        .expect_err("closed enum");
        assert!(err.to_string().contains("turbo"), "{err}");
    }

    #[test]
    fn an_unknown_key_in_an_assignment_does_not_deserialize() {
        serde_json::from_value::<Assignment>(json!({
            "provider": "codex", "model": "gpt-5.5", "sandbox": "danger"
        }))
        .expect_err("deny_unknown_fields");
    }

    /// Forward tolerance within v1: an unknown *team* key is carried, not refused.
    #[test]
    fn an_unknown_key_in_the_team_is_tolerated() {
        let team = team_json(json!({
            "version": 1, "name": "t", "roles": {}, "notes": "written by something newer"
        }));
        assert_eq!(team.name, "t");
    }

    #[test]
    fn an_assignment_without_an_effort_serializes_without_the_key() {
        let json = serde_json::to_value(Assignment {
            provider: ProviderName::Claude,
            model: "sonnet".to_owned(),
            effort: None,
        })
        .expect("json");
        assert_eq!(json, json!({ "provider": "claude", "model": "sonnet" }));
    }

    // -- the file ----------------------------------------------------------

    #[test]
    fn a_missing_file_is_none_not_an_error() {
        let dir = TempDir::new().expect("tempdir");
        assert!(load_team(dir.path()).expect("load").is_none());
    }

    #[test]
    fn a_newer_version_is_refused_and_left_untouched() {
        let dir = TempDir::new().expect("tempdir");
        let path = team_path(dir.path());
        let bytes = br#"{"version":4,"name":"future","crew":[{"role":"builder"}]}"#;
        fs::write(&path, bytes).expect("write");

        let err = load_team(dir.path()).expect_err("refused");
        assert!(
            matches!(
                err,
                TeamError::UnsupportedVersion {
                    found: 4,
                    supported: 3
                }
            ),
            "{err}"
        );
        assert_eq!(fs::read(&path).expect("read"), bytes, "bytes were touched");

        // And a save over it is refused too, with the same distinction.
        let err = save_team(dir.path(), &team_json(brief_team())).expect_err("refused");
        assert!(matches!(err, TeamError::UnsupportedVersion { .. }), "{err}");
        assert_eq!(fs::read(&path).expect("read"), bytes, "bytes were touched");
        assert_eq!(
            temp_files(dir.path()),
            0,
            "a temporary file was left behind"
        );
    }

    #[test]
    fn a_malformed_file_is_invalid_and_never_renamed() {
        let dir = TempDir::new().expect("tempdir");
        let path = team_path(dir.path());
        fs::write(&path, b"{ not json").expect("write");

        let err = load_team(dir.path()).expect_err("refused");
        assert!(matches!(err, TeamError::Invalid(_)), "{err}");
        assert_eq!(fs::read(&path).expect("read"), b"{ not json");
        assert_eq!(
            fs::read_dir(dir.path()).expect("read_dir").count(),
            1,
            "something was renamed or quarantined"
        );

        // Saving over bytes nothing can reproduce is refused rather than done.
        let err = save_team(dir.path(), &team_json(brief_team())).expect_err("refused");
        assert!(matches!(err, TeamError::Invalid(_)), "{err}");
        assert_eq!(fs::read(&path).expect("read"), b"{ not json");
        assert_eq!(
            temp_files(dir.path()),
            0,
            "a temporary file was left behind"
        );
    }

    #[test]
    fn save_then_load_round_trips_at_0600() {
        let dir = TempDir::new().expect("tempdir");
        let state = dir.path().join("state");
        let team = team_json(brief_team());

        save_team(&state, &team).expect("save");
        let mode = fs::metadata(team_path(&state))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "team.json is not 0600");
        assert_eq!(load_team(&state).expect("load"), Some(team.clone()));

        // Re-saving an unchanged team is byte-identical, and replaces the file in place.
        let first = fs::read(team_path(&state)).expect("read");
        save_team(&state, &team).expect("save again");
        assert_eq!(fs::read(team_path(&state)).expect("read"), first);
        assert_eq!(temp_files(&state), 0);
    }

    /// The file the daemon writes is the file the app reads: same keys, same spellings, and no
    /// `effort` key at all where there is no effort.
    #[test]
    fn the_saved_file_has_the_shape_the_app_writes() {
        let dir = TempDir::new().expect("tempdir");
        save_team(dir.path(), &team_json(brief_team())).expect("save");
        let value: Value =
            serde_json::from_slice(&fs::read(team_path(dir.path())).expect("read")).expect("json");

        assert_eq!(value["version"], json!(1));
        assert_eq!(value["name"], json!("Opus builds, Codex reviews"));
        assert_eq!(
            value["lead"],
            json!({ "provider": "claude", "model": "opus" })
        );
        assert_eq!(
            value["roles"]["builder"],
            json!({ "provider": "claude", "model": "sonnet" })
        );
        assert_eq!(
            value["roles"]["reviewer"],
            json!({ "provider": "codex", "model": "gpt-5.5", "effort": "high" })
        );
    }

    #[test]
    fn an_unwritable_state_dir_is_an_io_error_naming_the_path() {
        let dir = TempDir::new().expect("tempdir");
        let state = dir.path().join("state");
        fs::create_dir(&state).expect("mkdir");
        fs::set_permissions(&state, Permissions::from_mode(0o500)).expect("chmod");

        let err = save_team(&state, &team_json(brief_team())).expect_err("read-only");
        assert!(matches!(err, TeamError::Io(_)), "{err}");
        assert!(err.to_string().contains("team.json.tmp-"), "{err}");

        fs::set_permissions(&state, Permissions::from_mode(0o700)).expect("chmod");
    }

    fn temp_files(dir: &Path) -> usize {
        fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count()
    }

    // -- the catalog -------------------------------------------------------

    #[test]
    fn roles_list_preserves_the_legacy_catalog_shape() {
        let cfg = cfg();
        let available =
            BTreeMap::from([(ProviderName::Claude, true), (ProviderName::Codex, false)]);
        let value = serde_json::to_value(roles_list(&cfg, &available)).expect("json");

        // Field-by-field against the frozen public protocol fixture.
        let fallback: Value = serde_json::from_str(include_str!(
            "../../fixtures/catalog/roles-v1.json"
        ))
        .expect("fallback json");

        let keys = |v: &Value| {
            let mut keys: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
            keys.sort();
            keys
        };
        let mut legacy = value.clone();
        let lead = legacy.as_object_mut().unwrap().remove("lead").unwrap();
        assert_eq!(legacy.as_object_mut().unwrap().remove("humanSetupVersion"), Some(serde_json::json!(1)));
        assert_eq!(lead["name"], "lead");
        assert_eq!(lead["writes"], false);
        assert!(lead["models"].as_array().unwrap().contains(&json!("gpt-5.5")));
        assert_eq!(keys(&legacy), keys(&fallback), "lead is an additive catalog field");
        assert_eq!(
            keys(&value["roles"][0]),
            keys(&fallback["roles"][0]),
            "a role entry does not match the app's RoleSpec"
        );
        assert_eq!(
            keys(&value["providers"]["codex"]),
            keys(&fallback["providers"]["codex"]),
            "a provider entry does not match the app's ProviderSpec"
        );

        let roles = value["roles"].as_array().expect("roles");
        assert_eq!(roles.len(), 4, "the lead is not a worker role");
        assert_eq!(roles[0]["name"], json!("builder"));
        assert_eq!(roles[0]["provider"], json!("claude"));
        assert_eq!(roles[0]["defaultModel"], json!("sonnet"));
        assert_eq!(roles[0]["writes"], json!(true));
        assert_eq!(roles[1]["name"], json!("reviewer"));
        assert_eq!(roles[1]["writes"], json!(false));
        assert!(
            roles[1]["description"].is_string(),
            "the app's picker shows a description for every role"
        );
        // B1: the verifier is team-assignable, so the app's picker lists it (sorted by name).
        assert_eq!(roles[3]["name"], json!("verifier"));
        assert_eq!(roles[3]["writes"], json!(false));
        assert_eq!(roles[3]["defaultModel"], json!("haiku"));
        assert!(roles[3]["description"].is_string());

        assert_eq!(roles[2]["name"], json!("security"));
        assert_eq!(roles[2]["writes"], json!(false));
        assert_eq!(value["providers"]["claude"]["efforts"], json!([]));
        assert_eq!(value["providers"]["claude"]["available"], json!(true));
        assert_eq!(value["providers"]["codex"]["available"], json!(false));
        assert_eq!(
            value["providers"]["codex"]["efforts"],
            fallback["providers"]["codex"]["efforts"]
        );
    }

    /// A provider nobody probed is reported unavailable rather than assumed present.
    #[test]
    fn an_unprobed_provider_is_unavailable() {
        let cfg = cfg();
        let list = roles_list(&cfg, &BTreeMap::new());
        assert!(list.providers.values().all(|p| !p.available));
    }

    // -- per-model efforts (Revision 28) ---------------------------------------------------

    /// `max` joined the closed enum; `ultra` (Codex's self-delegating level) deliberately did not.
    #[test]
    fn max_is_a_closed_effort_and_ultra_is_not() {
        assert_eq!(
            serde_json::from_value::<Effort>(json!("max")).expect("max"),
            Effort::Max
        );
        assert_eq!(Effort::Max.as_str(), "max");
        assert!(serde_json::from_value::<Effort>(json!("ultra")).is_err());
    }

    /// A model that narrows its provider's list is checked against its own list, and the refusal
    /// names the model — "codex does not accept max" would be false for the models that do.
    #[test]
    fn an_effort_the_model_does_not_take_is_refused_by_model_name() {
        let cfg = cfg();
        let issues = validate_team(
            &cfg,
            &team_json(json!({
                "version": 1, "name": "t",
                "roles": { "reviewer": { "provider": "codex", "model": "gpt-5.5", "effort": "max" } }
            })),
        )
        .expect_err("gpt-5.5 takes no max");
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].code, TeamIssueCode::EffortNotAllowed);
        assert!(
            issues[0].detail.contains("gpt-5.5") && issues[0].detail.contains("`max`"),
            "{}",
            issues[0].detail
        );

        validate_team(
            &cfg,
            &team_json(json!({
                "version": 1, "name": "t",
                "roles": { "reviewer": { "provider": "codex", "model": "gpt-6-astra", "effort": "max" } }
            })),
        )
        .expect("gpt-6-astra takes max");

        // The lead is checked the same way.
        let issues = validate_team(
            &cfg,
            &team_json(json!({
                "version": 3, "mode": "plan", "name": "t",
                "lead": { "provider": "codex", "model": "gpt-5.3-codex-spark", "effort": "max" },
                "roles": {}
            })),
        )
        .expect_err("spark takes no max");
        assert_eq!(issues[0].code, TeamIssueCode::EffortNotAllowed);
    }

    /// `roles.list` sends a model's own list only where it narrows the provider's; claude and a
    /// model that takes the whole list send nothing extra, so an older app keeps decoding.
    #[test]
    fn roles_list_carries_model_efforts_only_where_a_model_narrows_the_list() {
        let cfg = cfg();
        let available =
            BTreeMap::from([(ProviderName::Claude, true), (ProviderName::Codex, true)]);
        let value = serde_json::to_value(roles_list(&cfg, &available)).expect("json");
        let codex = &value["providers"]["codex"];
        assert_eq!(codex["efforts"], json!(["low", "medium", "high", "xhigh", "max"]));
        assert_eq!(codex["modelEfforts"]["gpt-5.5"], json!(["low", "medium", "high", "xhigh"]));
        assert_eq!(
            codex["modelEfforts"]["gpt-5.3-codex-spark"],
            json!(["low", "medium", "high", "xhigh"])
        );
        assert!(codex["modelEfforts"].get("gpt-6-astra").is_none());
        assert!(value["providers"]["claude"].get("modelEfforts").is_none());

        // The answer decodes back into the type `acp start` reads, per-model lookup included.
        let decoded: RolesListResult = serde_json::from_value(value).expect("decodes");
        let codex = &decoded.providers[&ProviderName::Codex];
        assert_eq!(
            codex.efforts_for("gpt-5.5"),
            [Effort::Low, Effort::Medium, Effort::High, Effort::Xhigh]
        );
        assert_eq!(codex.efforts_for("gpt-6-astra").last(), Some(&Effort::Max));
        assert!(decoded.providers[&ProviderName::Claude].efforts_for("haiku").is_empty());
    }
}
