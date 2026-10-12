//! T49: the team layer — `reports/03-design.md` § "Team layer (Revision 26)".
//!
//! Two halves, and the seam between them is the point:
//!
//! * **the file and the chokepoint**, exercised through the crate's public API from *outside* the
//!   crate, over temp state dirs — `save_team`/`load_team`'s version gates, the issue codes, and
//!   `resolve_assignment`'s fallback to the role defaults;
//! * **the three socket-only methods**, driven over a **real Unix socket** by a hand-written NDJSON
//!   client, because `roles.list`, `team.get` and `team.set` are a wire contract that the Swift app
//!   decodes field for field (`apps/acp-mac/ACPProtocol/Sources/Wire/ACPMethods.swift`,
//!   `…/Team/{Team,RoleCatalog}.swift`).
//!
//! And one end-to-end test for the claim the whole layer exists to make: a `team.set` over the
//! socket decides the **provider, model and reasoning effort of the next worker the loop spawns**,
//! with no restart in between — the loop re-reads `team.json` at every spawn
//! (`core::loop::valid_team`, `core::loop::spawn_for_agent`), and this is what proves it rather
//! than quoting it.
//!
//! **What is deliberately not here.** That `roles.list`/`team.get`/`team.set` are absent from the
//! MCP tool list is pinned by `tests/mcp_server.rs`
//! (`tools_list_is_exactly_the_seven_the_design_fixes`, which names all three), against a real
//! rmcp `tools/list` over a duplex transport. `AcpServer::tool_router()` is private to the crate,
//! so a second assertion here could only re-run that same duplex handshake for a weaker claim.
//!
//! **The socket path must be short**: macOS `sun_path` is 104 bytes and `$TMPDIR` is a ~50-byte
//! `/var/folders/…` path, so every door here binds under `/tmp/<8 chars>` ([`short_dir`]), the
//! same rule `tests/socket.rs` follows.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_control_plane::core::registry::EVENT_CHANNEL_CAPACITY;
use agent_control_plane::core::team::{
    load_team, resolve_assignment, roles_list, save_team, team_path, validate_team, Assignment,
    Effort, Team, TeamError, TeamIssueCode, TEAM_FILE, TEAM_VERSION,
};
use agent_control_plane::core::types::{
    Event, EventPayload, GateKind, ProviderName, RoleName, RolesConfig, RunId, RunSteps,
};
use agent_control_plane::core::{channel, Command, CoreHandle};
use agent_control_plane::ipc::socket::{
    serve_socket, IpcError, ServerIdentity, MAX_SOCKET_PATH_BYTES,
};
use agent_control_plane::roles::loader::load_roles;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use common::{
    delegate_builder, embedded_roles, install_fake_clis, loop_task, quiesce, start_actor,
    ActorOpts, LoopWorld,
};

/// How long one wire round trip may take before the test calls it a hang. A failure detector, never
/// a timing assertion.
const LIMIT: Duration = Duration::from_secs(60);

/// The bound on the one test that drives real (fake) provider processes. Longer than [`LIMIT`] for
/// the reason `tests/socket.rs` records: spawning the fake CLIs on this platform is bimodal
/// (~1.5 s warm, 40-50 s cold), and this test waits for two workers in sequence.
const LIVE_LIMIT: Duration = Duration::from_secs(240);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn cfg() -> Arc<RolesConfig> {
    load_roles(None).expect("the embedded roles config")
}

/// The example from the app brief § 3 — the file the daemon must accept unchanged, and the shape
/// `apps/acp-mac/…/Team/Team.swift` encodes.
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

fn team_of(value: Value) -> Team {
    serde_json::from_value(value).expect("a team")
}

/// A temp state dir. `tempfile` creates it 0700, which is the mode the design requires.
fn state_dir() -> TempDir {
    tempfile::tempdir().expect("tempdir for $ACP_STATE_DIR")
}

/// Everything in `dir` whose name carries the `save_team` temporary marker.
fn temp_files(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .expect("read_dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp-"))
        .collect()
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

/// A save creates the state dir 0700, the file 0600, and leaves nothing else behind — and what
/// comes back out of `load_team` is what went in.
#[test]
fn save_then_load_round_trips_at_0600_leaving_no_temporary_file() {
    let dir = state_dir();
    // A path the daemon has to create itself, which is what `serve` does on first start.
    let state = dir.path().join("state");
    let team = team_of(brief_team());

    save_team(&state, &team).expect("save");

    assert_eq!(mode_of(&state), 0o700, "the state dir is not 0700");
    assert_eq!(mode_of(&team_path(&state)), 0o600, "team.json is not 0600");
    assert_eq!(load_team(&state).expect("load"), Some(team.clone()));
    assert_eq!(
        fs::read_dir(&state)
            .expect("read_dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        vec![TEAM_FILE.to_string()],
        "the state dir holds the team file and nothing else"
    );

    // Re-saving an unchanged team is byte-identical: the file is diffable, and a client that saves
    // on every keystroke does not churn the bytes.
    let first = fs::read(team_path(&state)).expect("read");
    save_team(&state, &team).expect("save again");
    assert_eq!(fs::read(team_path(&state)).expect("read"), first);
    assert_eq!(temp_files(&state), Vec::<String>::new());
}

/// The version gate is on **both** doors, and neither of them touches the bytes.
///
/// The case that matters is not a corrupt file: it is a human who opened the Team Builder in an old
/// build (holding a stale draft) while a newer one had already written v3. `load_team` says "update
/// acp", and `save_team` re-reads immediately before the rename and refuses the same way — a
/// refusal at load alone would let the stale draft win the race it was always going to lose.
#[test]
fn a_stale_v1_draft_never_overwrites_a_newer_file_on_disk() {
    let dir = state_dir();
    let state = dir.path();
    // Shaped like a format this build has never seen, not merely renumbered.
    let newer = br#"{"version":4,"name":"from the future","crew":[{"role":"builder"}]}"#;
    fs::write(team_path(state), newer).expect("write");

    let err = load_team(state).expect_err("a newer file is refused");
    assert!(
        matches!(
            err,
            TeamError::UnsupportedVersion {
                found: 4,
                supported: TEAM_VERSION
            }
        ),
        "load reported {err}"
    );

    let err = save_team(state, &team_of(brief_team())).expect_err("a stale draft is refused");
    assert!(
        matches!(err, TeamError::UnsupportedVersion { found: 4, .. }),
        "save reported {err}"
    );

    assert_eq!(
        fs::read(team_path(state)).expect("read"),
        newer,
        "the newer file was written over"
    );
    assert_eq!(
        temp_files(state),
        Vec::<String>::new(),
        "a temporary file was left behind"
    );
}

/// A file that is not a team at all is `Invalid` — a different remedy from "update acp" — and it is
/// never renamed, quarantined or replaced. Quarantine is the app's business; it has a human.
#[test]
fn a_malformed_file_is_invalid_on_load_and_refuses_a_save() {
    let dir = state_dir();
    let state = dir.path();
    let broken = b"{ not json";
    fs::write(team_path(state), broken).expect("write");

    assert!(
        matches!(
            load_team(state).expect_err("refused"),
            TeamError::Invalid(_)
        ),
        "a broken file is not an UnsupportedVersion"
    );
    assert!(
        matches!(
            save_team(state, &team_of(brief_team())).expect_err("refused"),
            TeamError::Invalid(_)
        ),
        "bytes nothing can reproduce were written over"
    );
    assert_eq!(fs::read(team_path(state)).expect("read"), broken);
    assert_eq!(
        fs::read_dir(state).expect("read_dir").count(),
        1,
        "something was renamed or quarantined"
    );
}

// ---------------------------------------------------------------------------
// The chokepoint
// ---------------------------------------------------------------------------

/// Every [`TeamIssueCode`] is reachable, reported per entry, and spelled on the wire exactly as
/// `TeamSetIssue.Code` in `apps/acp-mac/…/Wire/ACPMethods.swift` expects.
///
/// Two of the five need a **doctored config** to reach, and that is a fact about the shipped
/// `roles/roles.json` rather than about the checker: it lists every model of both providers under
/// every role (so no model is "in the catalog but not allowed for this role") and gives codex all
/// five efforts (so no effort is "not allowed"). Loosening the config is exactly what would make
/// those two codes fire in production, so they are tested here against a config loosened the other
/// way round.
#[test]
fn every_team_issue_code_is_produced_and_spelled_for_the_wire() {
    let mut doctored = (*cfg()).clone();
    // A provider the catalog does not carry at all: the only way to reach `unknown_provider`, since
    // `ProviderName` is a closed enum and an unknown *string* never gets past deserialization.
    doctored.providers.remove(&ProviderName::Claude);
    // A role allowlist narrower than the provider's catalog.
    doctored
        .roles
        .get_mut(&RoleName::Reviewer)
        .expect("the reviewer role")
        .models = vec!["gpt-5.5".to_string()];
    // A provider that takes efforts, but not all of them.
    doctored
        .providers
        .get_mut(&ProviderName::Codex)
        .expect("the codex catalog")
        .efforts = vec![Effort::Low, Effort::Medium];

    let issues = validate_team(
        &doctored,
        &team_of(json!({
            "version": 1,
            "name": "every way to be wrong",
            // claude is not in the catalog at all.
            "lead": { "provider": "claude", "model": "opus" },
            "roles": {
                // codex has no `haiku`; and the builder allows it, so this is one issue, not two.
                "builder": { "provider": "codex", "model": "haiku" },
                // in the codex catalog, outside the (narrowed) reviewer allowlist, and with an
                // effort this catalog no longer offers.
                "reviewer": {
                    "provider": "codex",
                    "model": "gpt-5.3-codex-spark",
                    "effort": "xhigh"
                }
            }
        })),
    )
    .expect_err("every assignment is wrong");

    let mut codes: Vec<&str> = issues.iter().map(|issue| issue.code.as_str()).collect();
    codes.sort_unstable();
    assert_eq!(
        codes,
        [
            "effort_not_allowed",
            "model_not_allowed_for_role",
            "model_not_in_provider",
            // C1 removed `provider_cannot_write` from this list: codex now has a measured
            // workspace-write plan, so a codex builder is a legal pairing. The issue code stays
            // wire-pinned below for the day a third provider arrives without a sandbox.
            "unknown_provider",
        ],
        "one issue per broken rule, none swallowed: {issues:?}"
    );
    assert_eq!(
        issues
            .iter()
            .find(|issue| issue.code == TeamIssueCode::UnknownProvider)
            .map(|issue| issue.role.as_str()),
        Some("lead"),
        "the lead's own key names it in an issue"
    );

    // The fifth code needs a provider that takes *no* effort, which the shipped catalog has.
    let issues = validate_team(
        &cfg(),
        &team_of(json!({
            "version": 1,
            "name": "an effort where there is none",
            "roles": { "builder": { "provider": "claude", "model": "sonnet", "effort": "high" } }
        })),
    )
    .expect_err("claude takes no reasoning effort");
    assert_eq!(
        issues.iter().map(|i| i.code.as_str()).collect::<Vec<_>>(),
        ["effort_unsupported"]
    );

    // The seventh code: v2 membership is explicit and the one writer is mandatory.
    let issues = validate_team(
        &cfg(),
        &team_of(json!({
            "version": 2,
            "name": "no writer",
            "roles": { "reviewer": { "provider": "codex", "model": "gpt-5.5" } }
        })),
    )
    .expect_err("a v2 team without a builder is refused");
    assert_eq!(
        issues.iter().map(|i| i.code.as_str()).collect::<Vec<_>>(),
        ["builder_required"]
    );

    // The eighth code: a v2 team's unknown key would otherwise silently disable a step.
    let issues = validate_team(
        &cfg(),
        &team_of(json!({
            "version": 2,
            "name": "typo'd reviewer",
            "roles": {
                "builder": { "provider": "claude", "model": "sonnet" },
                "reviewers": { "provider": "codex", "model": "gpt-5.5" }
            }
        })),
    )
    .expect_err("a v2 team with an unknown role key is refused");
    assert_eq!(
        issues.iter().map(|i| i.code.as_str()).collect::<Vec<_>>(),
        ["unknown_role"]
    );

    // The eight spellings the app branches on, pinned here rather than only inside the crate.
    // `builder_required`/`unknown_role` are the newest; the app's normalizer decodes issue codes
    // tolerantly, so an older build shows an unrecognised reason rather than failing to parse.
    assert_eq!(
        [
            TeamIssueCode::UnknownProvider,
            TeamIssueCode::ModelNotInProvider,
            TeamIssueCode::ModelNotAllowedForRole,
            TeamIssueCode::EffortUnsupported,
            TeamIssueCode::EffortNotAllowed,
            TeamIssueCode::ProviderCannotWrite,
            TeamIssueCode::BuilderRequired,
            TeamIssueCode::UnknownRole,
        ]
        .map(TeamIssueCode::as_str),
        [
            "unknown_provider",
            "model_not_in_provider",
            "model_not_allowed_for_role",
            "effort_unsupported",
            "effort_not_allowed",
            "provider_cannot_write",
            "builder_required",
            "unknown_role",
        ]
    );
}

/// C1's flip, on the public surface: the exact team that was the canonical
/// `provider_cannot_write` refusal for sixty tasks now validates.
#[test]
fn a_codex_builder_team_is_accepted_since_c1() {
    // Pre-C1 this exact team was the canonical `provider_cannot_write` refusal. The flip is the
    // point: codex now carries the measured workspace-write plan, so the pairing validates and
    // the confinement is enforced where it always was — at the spawn chokepoint (V4).
    let team = validate_team(
        &cfg(),
        &team_of(json!({
            "version": 1,
            "name": "a builder that now starts",
            "roles": { "builder": { "provider": "codex", "model": "gpt-5.5", "effort": "low" } }
        })),
    )
    .expect("a codex builder is a legal team since C1");
    assert!(team.ignored_roles.is_empty());
}

/// With no team, and for a role a team does not name, the spawn is the role's own defaults.
#[test]
fn resolve_assignment_falls_back_to_the_role_defaults() {
    let cfg = cfg();
    let defaults = |role| resolve_assignment(&cfg, None, role);

    assert_eq!(
        defaults(RoleName::Builder),
        Assignment {
            provider: ProviderName::Claude,
            model: "sonnet".to_string(),
            effort: None,
        }
    );
    assert_eq!(
        defaults(RoleName::Reviewer),
        Assignment {
            provider: ProviderName::Codex,
            model: "gpt-5.5".to_string(),
            effort: None,
        }
    );

    // A team that names only the reviewer moves only the reviewer.
    let partial = validate_team(
        &cfg,
        &team_of(json!({
            "version": 1,
            "name": "reviewer only",
            "roles": {
                "reviewer": { "provider": "codex", "model": "gpt-5.3-codex-spark",
                              "effort": "xhigh" }
            }
        })),
    )
    .expect("valid");
    assert_eq!(
        resolve_assignment(&cfg, Some(&partial), RoleName::Builder),
        defaults(RoleName::Builder),
        "an unnamed role keeps its default"
    );
    assert_eq!(
        resolve_assignment(&cfg, Some(&partial), RoleName::Reviewer),
        Assignment {
            provider: ProviderName::Codex,
            model: "gpt-5.3-codex-spark".to_string(),
            effort: Some(Effort::Xhigh),
        }
    );
    assert!(
        partial.assignment(RoleName::Builder).is_none(),
        "a role the team does not name has no checked assignment"
    );

    // A role key this build does not spawn is ignored — never fatal, and never resolvable.
    let with_unknown = validate_team(
        &cfg,
        &team_of(json!({
            "version": 1,
            "name": "written for a later build",
            "roles": {
                "builder": { "provider": "claude", "model": "haiku" },
                "critic": { "provider": "claude", "model": "opus" }
            }
        })),
    )
    .expect("an unknown role is not fatal");
    assert_eq!(with_unknown.ignored_roles, vec!["critic".to_string()]);
    assert_eq!(
        resolve_assignment(&cfg, Some(&with_unknown), RoleName::Builder).model,
        "haiku",
        "the roles both builds share still resolve"
    );
}

/// `roles.list` is the app's `RoleCatalog` — the same document as its bundled
/// `roles.fallback.json`, key for key. The two are decoded by one Swift type, so a drift here is a
/// picker that cannot be filled from the daemon.
#[test]
fn roles_list_keeps_the_legacy_worker_catalog_and_adds_a_separate_lead() {
    let cfg = cfg();
    let available = BTreeMap::from([(ProviderName::Claude, true), (ProviderName::Codex, false)]);
    let answer = serde_json::to_value(roles_list(&cfg, &available)).expect("json");

    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/catalog/roles-v1.json");
    let fallback: Value = serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display())),
    )
    .expect("the bundled catalog is JSON");

    let keys = |value: &Value| {
        let mut keys: Vec<String> = value
            .as_object()
            .unwrap_or_else(|| panic!("not an object: {value}"))
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    let mut legacy_shape = answer.clone();
    legacy_shape.as_object_mut().unwrap().remove("lead");
    legacy_shape.as_object_mut().unwrap().remove("humanSetupVersion");
    assert_eq!(keys(&legacy_shape), keys(&fallback), "existing catalog fields remain compatible");
    assert_eq!(answer["lead"]["name"], "lead");
    assert_eq!(answer["lead"]["writes"], false);
    let old: agent_control_plane::core::team::RolesListResult = serde_json::from_value(fallback.clone()).unwrap();
    assert!(old.lead.is_none(), "old catalogs still decode without a spawned-lead offer");

    for role in answer["roles"].as_array().expect("roles") {
        let name = role["name"].as_str().expect("a role name");
        let same = fallback["roles"]
            .as_array()
            .expect("roles")
            .iter()
            .find(|entry| entry["name"] == role["name"])
            .unwrap_or_else(|| panic!("the app's catalog has no `{name}` role"));
        assert_eq!(keys(role), keys(same), "the `{name}` entry differs");
        assert_eq!(role["provider"], same["provider"], "`{name}` provider");
        assert_eq!(role["models"], same["models"], "`{name}` models");
        assert!(
            role["description"].is_string(),
            "the app's picker shows a description for every role"
        );
    }

    assert_eq!(
        keys(&answer["providers"]),
        keys(&fallback["providers"]),
        "the provider catalogs name different providers"
    );
    for (name, provider) in answer["providers"].as_object().expect("providers") {
        let same = &fallback["providers"][name];
        assert_eq!(keys(provider), keys(same), "the `{name}` catalog differs");
        assert_eq!(provider["models"], same["models"], "`{name}` models");
        assert_eq!(provider["efforts"], same["efforts"], "`{name}` efforts");
        // Revision 28: the per-model narrowing must agree too (absent on both sides for claude),
        // or the two files could narrow different models and this drift guard would stay green.
        assert_eq!(
            provider["modelEfforts"], same["modelEfforts"],
            "`{name}` modelEfforts"
        );
    }

    // `available` is this machine, not the bundle: it is whatever was probed, per call.
    assert_eq!(answer["providers"]["claude"]["available"], json!(true));
    assert_eq!(answer["providers"]["codex"]["available"], json!(false));

    // The spawned-lead catalog is separate from worker membership.
    let names: Vec<&str> = answer["roles"]
        .as_array()
        .expect("roles")
        .iter()
        .map(|role| role["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        ["builder", "reviewer", "security", "verifier"],
        "sorted, and no lead"
    );
}

// ---------------------------------------------------------------------------
// A door
// ---------------------------------------------------------------------------

/// A temp directory under `/tmp`, short enough that `<dir>/acp.sock` fits in `sun_path`.
fn short_dir() -> TempDir {
    let dir = tempfile::Builder::new()
        .prefix("acp")
        .rand_bytes(5)
        .tempdir_in("/tmp")
        .expect("a short temp dir under /tmp");
    let socket = dir.path().join("acp.sock").into_os_string();
    assert!(
        socket.len() <= MAX_SOCKET_PATH_BYTES,
        "the fixture path is {} bytes, over the limit the daemon enforces",
        socket.len()
    );
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
        .expect("0700 on the fixture state dir");
    dir
}

/// One running `serve_socket`, with the directory it is bound in.
///
/// The door's own directory is also its state dir unless the caller says otherwise, which is the
/// production layout: `$ACP_STATE_DIR/acp.sock` beside `$ACP_STATE_DIR/team.json`.
struct Door {
    dir: TempDir,
    state_dir: PathBuf,
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), IpcError>>,
    /// The mailbox of a core nothing here ever sends to: the three team methods are answered by the
    /// door itself. Held so the handle does not read as closed.
    _core: mpsc::Receiver<Command>,
    _events: broadcast::Sender<Arc<Event>>,
}

impl Door {
    /// A door over its own temp directory, offering the team layer over the embedded config.
    fn start() -> Self {
        let dir = short_dir();
        let state_dir = dir.path().to_path_buf();
        Self::new(dir, state_dir, Some(embedded_roles()))
    }

    /// A door whose `stateDir` — where `team.json` lives — is somewhere else entirely: the loop's
    /// own state dir, which `tests/common` puts under `$TMPDIR`, where a socket path may not fit.
    fn over_state_dir(state_dir: &Path, roles: Arc<RolesConfig>) -> Self {
        Self::new(short_dir(), state_dir.to_path_buf(), Some(roles))
    }

    /// A door the daemon forgot to hand a roles configuration to.
    fn without_roles() -> Self {
        let dir = short_dir();
        let state_dir = dir.path().to_path_buf();
        Self::new(dir, state_dir, None)
    }

    fn new(dir: TempDir, state_dir: PathBuf, roles: Option<Arc<RolesConfig>>) -> Self {
        let (tx, rx) = channel();
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let core = CoreHandle::new(tx, events.clone());
        let identity = ServerIdentity::new(PathBuf::from("/fixture/repo"), state_dir.clone());
        let identity = match roles {
            Some(roles) => identity.with_roles(roles),
            None => identity,
        };
        let shutdown = CancellationToken::new();
        let path = dir.path().join("acp.sock");
        let token = shutdown.clone();
        let task = tokio::spawn(async move { serve_socket(&path, core, identity, token).await });
        Self {
            dir,
            state_dir,
            shutdown,
            task,
            _core: rx,
            _events: events,
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("acp.sock")
    }

    /// Where this door reads and writes `team.json`.
    fn team_file(&self) -> PathBuf {
        team_path(&self.state_dir)
    }

    async fn stop(self) -> Result<(), IpcError> {
        self.shutdown.cancel();
        tokio::time::timeout(LIMIT, self.task)
            .await
            .expect("serve_socket stopped")
            .expect("the socket task did not panic")
    }
}

/// One NDJSON connection, written and parsed by hand — no client library between the test and the
/// bytes.
struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: i64,
}

impl Client {
    /// Connects, retrying until the door's `bind` has happened (it runs in a spawned task).
    async fn connect(path: &Path) -> Self {
        let deadline = Instant::now() + LIMIT;
        loop {
            match UnixStream::connect(path).await {
                Ok(stream) => {
                    let (reader, writer) = stream.into_split();
                    return Self {
                        reader: BufReader::new(reader),
                        writer,
                        next_id: 1,
                    };
                }
                Err(err) => {
                    assert!(
                        Instant::now() < deadline,
                        "never connected to {}: {err}",
                        path.display()
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// One JSON-RPC call: `Ok(result)` or `Err(error object)`. Notifications arriving in between
    /// are discarded — nothing here subscribes.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        let id = self.next_id;
        self.next_id += 1;
        let line =
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        self.writer
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write a frame");
        loop {
            let mut buf = String::new();
            let read = tokio::time::timeout(LIMIT, self.reader.read_line(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("no answer to `{method}` within {LIMIT:?}"))
                .expect("read a frame");
            assert!(read > 0, "the door closed while answering `{method}`");
            let frame: Value = serde_json::from_str(&buf)
                .unwrap_or_else(|err| panic!("frame is JSON: {err}: {buf}"));
            if frame.get("id").and_then(Value::as_i64) != Some(id) {
                continue;
            }
            return match frame.get("error") {
                Some(error) => Err(error.clone()),
                None => Ok(frame.get("result").cloned().unwrap_or(Value::Null)),
            };
        }
    }
}

/// Connects and says `hello`, as every client must before anything it does is attributable.
async fn client_of(door: &Door) -> Client {
    let mut client = Client::connect(&door.path()).await;
    client
        .call(
            "hello",
            json!({ "clientName": "acp-mac", "clientVersion": "0.1.0" }),
        )
        .await
        .expect("hello");
    client
}

fn block_on<Fut: std::future::Future<Output = ()>>(fut: Fut) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(fut);
}

// ---------------------------------------------------------------------------
// roles.list
// ---------------------------------------------------------------------------

/// The catalog over the wire, with `available` probed on **this** call: the fake CLIs are on `PATH`
/// for this test binary, and that is what the door must report.
#[test]
fn roles_list_over_the_socket_probes_path_on_every_call() {
    common::with_shared_env(|| async {
        install_fake_clis();
        let door = Door::start();
        let mut client = client_of(&door).await;

        let answer = client
            .call("roles.list", json!({}))
            .await
            .expect("roles.list");
        assert_eq!(
            answer["roles"]
                .as_array()
                .expect("roles")
                .iter()
                .map(|role| role["name"].as_str().expect("a name"))
                .collect::<Vec<_>>(),
            ["builder", "reviewer", "security", "verifier"]
        );
        assert_eq!(answer["providers"]["claude"]["available"], json!(true));
        assert_eq!(answer["providers"]["codex"]["available"], json!(true));
        assert_eq!(
            answer["providers"]["codex"]["efforts"],
            json!(["low", "medium", "high", "xhigh", "max"])
        );

        // `params` may be absent entirely, and an argument nobody defined is refused rather than
        // ignored — a client filtering on a key the daemon does not have must hear about it.
        assert_eq!(
            client
                .call("roles.list", Value::Null)
                .await
                .expect("no params"),
            answer
        );
        let err = client
            .call("roles.list", json!({ "provider": "codex" }))
            .await
            .expect_err("an unknown argument");
        assert_eq!(err["code"], json!(-32602), "{err}");

        door.stop().await.expect("the door stopped");
    });
}

/// A provider whose CLI is not on `PATH` is reported unavailable — the probe is real, not a
/// constant. This is the `doctor` answer the app shows beside a provider it cannot pick.
#[test]
fn a_provider_that_is_not_on_path_is_unavailable() {
    common::with_exclusive_env(|| async {
        // Absolute, empty, and not a directory anything of ours lives in: `find_on_path` searches
        // absolute entries only, so this is a `PATH` on which no provider exists.
        let empty = tempfile::tempdir().expect("an empty bin dir");
        let restore = PathGuard::set(empty.path());

        let door = Door::start();
        let mut client = client_of(&door).await;
        let answer = client
            .call("roles.list", json!({}))
            .await
            .expect("roles.list");

        assert_eq!(answer["providers"]["claude"]["available"], json!(false));
        assert_eq!(answer["providers"]["codex"]["available"], json!(false));
        assert!(
            !answer["roles"].as_array().expect("roles").is_empty(),
            "the catalog is still served: what is missing is the CLI, not the config"
        );

        drop(restore);
        door.stop().await.expect("the door stopped");
    });
}

/// Restores `$PATH` even if the test between here and the drop panics — a leaked bogus `PATH` would
/// fail every later test in this binary for the wrong reason.
struct PathGuard(Option<std::ffi::OsString>);

impl PathGuard {
    fn set(dir: &Path) -> Self {
        let guard = Self(std::env::var_os("PATH"));
        std::env::set_var("PATH", dir);
        guard
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(path) => std::env::set_var("PATH", path),
            None => std::env::remove_var("PATH"),
        }
    }
}

// ---------------------------------------------------------------------------
// team.get / team.set
// ---------------------------------------------------------------------------

/// Before anything is written: `{team: null, path}` — and `path` is the authority for where a
/// client that writes the file itself should write it.
#[test]
fn team_get_is_null_until_something_is_written() {
    block_on(async {
        let door = Door::start();
        let mut client = client_of(&door).await;

        let answer = client.call("team.get", json!({})).await.expect("team.get");
        assert_eq!(answer["team"], Value::Null);
        assert_eq!(answer["path"], json!(door.team_file()));
        assert!(!door.team_file().exists(), "a read created the file");

        door.stop().await.expect("the door stopped");
    });
}

/// A valid team is written 0600 and comes back out of `team.get` exactly as it was submitted.
#[test]
fn a_valid_team_set_writes_0600_and_team_get_returns_it_unchanged() {
    block_on(async {
        let door = Door::start();
        let mut client = client_of(&door).await;
        let submitted = brief_team();

        let answer = client
            .call("team.set", json!({ "team": submitted }))
            .await
            .expect("team.set");
        assert_eq!(answer, json!({ "ok": true, "ignoredRoles": [] }));

        assert_eq!(mode_of(&door.team_file()), 0o600, "team.json is not 0600");
        assert_eq!(
            temp_files(&door.state_dir),
            Vec::<String>::new(),
            "a temporary file was left behind"
        );

        let on_disk: Value =
            serde_json::from_slice(&fs::read(door.team_file()).expect("read")).expect("json");
        assert_eq!(on_disk, submitted, "the file is not what the client sent");
        assert_eq!(
            client.call("team.get", json!({})).await.expect("team.get")["team"],
            submitted,
            "team.get re-derived the team instead of echoing it"
        );

        // And the daemon's own reader agrees with the door: this is the file the loop will read.
        assert_eq!(
            load_team(&door.state_dir).expect("load"),
            Some(team_of(submitted))
        );

        door.stop().await.expect("the door stopped");
    });
}

/// An invalid team is `-32000 team_invalid`, lists **every** issue, and writes nothing at all.
#[test]
fn an_invalid_team_set_lists_every_issue_and_writes_nothing() {
    block_on(async {
        let door = Door::start();
        let mut client = client_of(&door).await;

        let err = client
            .call(
                "team.set",
                json!({
                    "team": {
                        "version": 1,
                        "name": "wrong twice",
                        "roles": {
                            // claude has no `gpt-5.5` …
                            "builder": { "provider": "claude", "model": "gpt-5.5" },
                            // … and claude takes no reasoning effort.
                            "reviewer": { "provider": "claude", "model": "opus", "effort": "high" }
                        }
                    }
                }),
            )
            .await
            .expect_err("the team is not allowed");

        assert_eq!(err["code"], json!(-32000), "{err}");
        assert_eq!(err["data"]["code"], json!("team_invalid"));
        let issues = err["data"]["issues"].as_array().expect("issues");
        assert_eq!(issues.len(), 2, "an issue was swallowed: {err}");
        assert_eq!(
            issues
                .iter()
                .map(|issue| (
                    issue["role"].as_str().expect("role"),
                    issue["code"].as_str().expect("code")
                ))
                .collect::<Vec<_>>(),
            [
                ("builder", "model_not_in_provider"),
                ("reviewer", "effort_unsupported")
            ]
        );
        for issue in issues {
            assert!(
                issue["detail"].as_str().is_some_and(|d| !d.is_empty()),
                "every issue names what a human has to fix: {issue}"
            );
        }
        assert!(
            err["message"]
                .as_str()
                .expect("a message")
                .contains("builder"),
            "the prose reason lists the rows too: {err}"
        );

        assert!(
            !door.team_file().exists(),
            "a refused team.set wrote the file anyway"
        );
        assert_eq!(temp_files(&door.state_dir), Vec::<String>::new());

        door.stop().await.expect("the door stopped");
    });
}

/// A role key this build does not spawn is reported and kept, never fatal and never dropped: the
/// file belongs to the human, and a daemon that knows fewer roles is not entitled to edit it.
#[test]
fn an_unknown_role_is_ignored_and_still_written() {
    block_on(async {
        let door = Door::start();
        let mut client = client_of(&door).await;
        let submitted = json!({
            "version": 1,
            "name": "written for a later build",
            "roles": {
                "builder": { "provider": "claude", "model": "haiku" },
                "critic": { "provider": "claude", "model": "opus" }
            }
        });

        let answer = client
            .call("team.set", json!({ "team": submitted }))
            .await
            .expect("an unknown role is not fatal");
        assert_eq!(answer, json!({ "ok": true, "ignoredRoles": ["critic"] }));
        assert_eq!(
            client.call("team.get", json!({})).await.expect("team.get")["team"],
            submitted,
            "the ignored entry was dropped from the human's file"
        );

        door.stop().await.expect("the door stopped");
    });
}

/// A file from a newer build is refused with its **own** code — "update acp", not "your team is
/// wrong" — and its bytes are left exactly as they were.
#[test]
fn team_set_refuses_to_write_over_a_newer_file() {
    block_on(async {
        let door = Door::start();
        let newer = br#"{"version":4,"name":"from the future","crew":[]}"#;
        fs::write(door.team_file(), newer).expect("write");

        let mut client = client_of(&door).await;
        let err = client
            .call("team.set", json!({ "team": brief_team() }))
            .await
            .expect_err("a newer file is not written over");
        assert_eq!(err["code"], json!(-32000), "{err}");
        assert_eq!(err["data"]["code"], json!("team_unsupported_version"));
        assert_eq!(err["data"]["found"], json!(4));
        assert_eq!(err["data"]["supported"], json!(TEAM_VERSION));

        // `team.get` says the same thing rather than reporting "no team", which would be a lie
        // about a file that exists.
        let err = client
            .call("team.get", json!({}))
            .await
            .expect_err("a newer file cannot be read either");
        assert_eq!(err["data"]["code"], json!("team_unsupported_version"));

        assert_eq!(fs::read(door.team_file()).expect("read"), newer);
        assert_eq!(temp_files(&door.state_dir), Vec::<String>::new());

        door.stop().await.expect("the door stopped");
    });
}

/// A file that is not a team at all is `team_invalid` on read, and is left alone.
#[test]
fn team_get_over_a_broken_file_is_team_invalid_and_leaves_it_alone() {
    block_on(async {
        let door = Door::start();
        fs::write(door.team_file(), b"{ not json").expect("write");

        let mut client = client_of(&door).await;
        let err = client
            .call("team.get", json!({}))
            .await
            .expect_err("a broken file is not `{team: null}`");
        assert_eq!(err["code"], json!(-32000), "{err}");
        assert_eq!(err["data"]["code"], json!("team_invalid"));
        assert_eq!(fs::read(door.team_file()).expect("read"), b"{ not json");

        door.stop().await.expect("the door stopped");
    });
}

/// A team the daemon cannot parse is `-32602`, before anything is validated or written: a closed
/// enum is what keeps an unattested provider, model spelling or effort out of an argv position.
#[test]
fn a_team_the_daemon_cannot_parse_is_invalid_params() {
    block_on(async {
        let door = Door::start();
        let mut client = client_of(&door).await;

        for (what, team) in [
            (
                "an unknown provider",
                json!({ "version": 1, "name": "n",
                        "roles": { "builder": { "provider": "anthropic", "model": "opus" } } }),
            ),
            (
                "an unknown effort",
                json!({ "version": 1, "name": "n",
                        "roles": { "builder": { "provider": "codex", "model": "gpt-5.5",
                                                "effort": "ludicrous" } } }),
            ),
            (
                "an unknown key in an assignment",
                json!({ "version": 1, "name": "n",
                        "roles": { "builder": { "provider": "claude", "model": "opus",
                                                "sandbox": "danger-full-access" } } }),
            ),
            ("no version at all", json!({ "name": "n", "roles": {} })),
        ] {
            match client.call("team.set", json!({ "team": team })).await {
                Ok(answer) => panic!("{what} was accepted: {answer}"),
                Err(err) => assert_eq!(err["code"], json!(-32602), "{what}: {err}"),
            }
        }
        assert!(
            !door.team_file().exists(),
            "a team that did not even parse reached the file"
        );

        door.stop().await.expect("the door stopped");
    });
}

/// A door started without a roles configuration does not offer the team layer **at all** — which is
/// exactly what an older daemon looks like to a newer app, and what the app already handles by
/// falling back to its bundled catalog.
#[test]
fn a_door_with_no_roles_configuration_offers_no_team_layer() {
    block_on(async {
        let door = Door::without_roles();
        let mut client = client_of(&door).await;

        for (method, params) in [
            ("roles.list", json!({})),
            ("team.get", json!({})),
            ("team.set", json!({ "team": brief_team() })),
        ] {
            match client.call(method, params).await {
                Ok(answer) => panic!("`{method}` was answered without a config: {answer}"),
                Err(err) => assert_eq!(err["code"], json!(-32601), "{method}: {err}"),
            }
        }
        assert!(
            !door.team_file().exists(),
            "a door with no config wrote a team file"
        );

        // The rest of the door is unaffected.
        client.call("hello", json!({})).await.expect("hello");
        door.stop().await.expect("the door stopped");
    });
}

// ---------------------------------------------------------------------------
// End to end: the team decides the next spawn
// ---------------------------------------------------------------------------

/// The claim the whole layer exists to make, proven through the real loop and the fake CLIs:
/// a `team.set` over the socket decides the **provider, model and reasoning effort** of the next
/// workers — with no restart, and for a team written *after* the daemon started.
///
/// Both halves matter and neither is the default:
///
/// * the builder is moved off `roles.json`'s `sonnet` onto `haiku`, so its `--model` proves the
///   team decided the model rather than the role;
/// * the reviewer is given `effort: high`, so its `-c model_reasoning_effort="high"` proves the
///   effort came from `team.json` rather than from the adapter's `medium` constant.
///
/// The reviewer is also the role the loop starts **by itself** — nothing in this test asks for
/// one — so the assertion covers the control plane's own spawns, not merely the door's.
#[test]
fn a_team_set_over_the_socket_decides_the_next_spawn() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let door = Door::over_state_dir(world.state_dir(), embedded_roles());
        let mut client = client_of(&door).await;

        // Written after the daemon is up: the loop re-reads `team.json` at every spawn.
        let answer = client
            .call(
                "team.set",
                json!({
                    "team": {
                        "version": 1,
                        "name": "T49",
                        "lead": { "provider": "claude", "model": "opus" },
                        "roles": {
                            "builder": { "provider": "claude", "model": "haiku" },
                            "reviewer": { "provider": "codex", "model": "gpt-5.5",
                                          "effort": "high" }
                        }
                    }
                }),
            )
            .await
            .expect("team.set");
        assert_eq!(answer["ok"], json!(true));

        let delegated = actor
            .handle
            .delegate(delegate_builder(loop_task("T49-team")))
            .await
            .expect("delegate");
        let run = delegated.run_id;

        // All three workers of a passing loop (B1): the builder this test asked for, the
        // verifier the control plane inserts after the build result lands, and the reviewer.
        let events = poll_log(
            &world,
            run,
            "the reviewer's attempt has started",
            |events| spawned(events).len() == 3,
        )
        .await;
        let spawns = spawned(&events);

        let (role, provider, model, argv) = &spawns[0];
        assert_eq!(
            (*role, *provider),
            (RoleName::Builder, ProviderName::Claude)
        );
        assert_eq!(
            model, "haiku",
            "the team's model, not roles.json's `sonnet`"
        );
        assert_eq!(
            after(argv, "--model"),
            Some("haiku"),
            "the worker's own argv carries the team's model"
        );

        // The team names no verifier, so the verify spawn runs on roles.json's own defaults —
        // which is itself the assertion: an unnamed role is untouched by the team.
        let (role, provider, model, _argv) = &spawns[1];
        assert_eq!(
            (*role, *provider),
            (RoleName::Verifier, ProviderName::Claude)
        );
        assert_eq!(
            model, "haiku",
            "roles.json's verifier default, not the team"
        );

        let (role, provider, model, argv) = &spawns[2];
        assert_eq!(
            (*role, *provider),
            (RoleName::Reviewer, ProviderName::Codex)
        );
        assert_eq!(model, "gpt-5.5");
        assert_eq!(after(argv, "-m"), Some("gpt-5.5"), "the reviewer's model");
        // One assertion for both halves: the team's effort is there, and the adapter's `medium`
        // constant is not. (`argv` is kept out of the message: it carries the whole role prompt.)
        assert_eq!(
            argv.iter()
                .filter(|token| token.starts_with("model_reasoning_effort"))
                .collect::<Vec<_>>(),
            [r#"model_reasoning_effort="high""#],
            "the effort in the reviewer's argv is not the team's"
        );

        quiesce(&actor.handle).await;
        actor.stop().await;
        door.stop().await.expect("the door stopped");
    });
}

/// Every worker the log shows as started, in order: `(role, provider, model, argv)`.
///
/// Joined from `agent.created` (which carries the resolved role, provider and model) and
/// `attempt.started` (which carries the argv the child was actually given).
fn spawned(events: &[Arc<Event>]) -> Vec<(RoleName, ProviderName, String, Vec<String>)> {
    let mut agents = HashMap::new();
    for event in events {
        if let EventPayload::AgentCreated {
            agent_id,
            role,
            provider,
            model,
            ..
        } = &event.payload
        {
            agents.insert(*agent_id, (*role, *provider, model.clone()));
        }
    }
    events
        .iter()
        .filter_map(|event| match &event.payload {
            EventPayload::AttemptStarted { agent_id, argv, .. } => agents
                .get(agent_id)
                .map(|(role, provider, model)| (*role, *provider, model.clone(), argv.clone())),
            _ => None,
        })
        .collect()
}

/// The token after `flag` in an argv, if it is there.
fn after<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|token| token == flag)
        .and_then(|index| argv.get(index + 1))
        .map(String::as_str)
}

/// Polls the durable log until `pred` holds. [`LIVE_LIMIT`] rather than `common::LIMIT` because two
/// real (fake) provider processes run in sequence inside this window.
async fn poll_log(
    world: &LoopWorld,
    run: RunId,
    what: &str,
    mut pred: impl FnMut(&[Arc<Event>]) -> bool,
) -> Vec<Arc<Event>> {
    let deadline = Instant::now() + LIVE_LIMIT;
    loop {
        let events = world.events(&run);
        if pred(&events) {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "{what} never happened within {LIVE_LIMIT:?}"
        );
        tokio::time::sleep(common::TICK).await;
    }
}

/// B3's switch: from v2 on, membership IS the step list. v1 keeps meaning "use the defaults" —
/// pinned so the upgrade cannot silently strip steps from existing files.
#[test]
fn step_enabled_reads_membership_only_from_version_2() {
    let cfg = cfg();
    let v1 = validate_team(
        &cfg,
        &team_of(json!({
            "version": 1,
            "name": "v1 defaults",
            "roles": { "builder": { "provider": "claude", "model": "sonnet" } }
        })),
    )
    .expect("a v1 team");
    assert!(v1.step_enabled(RoleName::Verifier));
    assert!(v1.step_enabled(RoleName::Reviewer));

    let solo = validate_team(
        &cfg,
        &team_of(json!({
            "version": 2,
            "name": "builder only",
            "roles": { "builder": { "provider": "claude", "model": "sonnet" } }
        })),
    )
    .expect("a v2 builder-only team");
    assert!(solo.step_enabled(RoleName::Builder));
    assert!(!solo.step_enabled(RoleName::Verifier));
    assert!(!solo.step_enabled(RoleName::Reviewer));

    let pair = validate_team(
        &cfg,
        &team_of(json!({
            "version": 2,
            "name": "build and review",
            "roles": {
                "builder": { "provider": "claude", "model": "sonnet" },
                "reviewer": { "provider": "codex", "model": "gpt-5.5" }
            }
        })),
    )
    .expect("a v2 build-and-review team");
    assert!(pair.step_enabled(RoleName::Reviewer));
    assert!(!pair.step_enabled(RoleName::Verifier));
}

/// A v2 file remains compatible: both doors take it, byte-preserved.
#[test]
fn a_version_2_team_round_trips_through_both_doors() {
    let dir = state_dir();
    let state = dir.path();
    let team = team_of(json!({
        "version": 2,
        "name": "builder only",
        "roles": { "builder": { "provider": "claude", "model": "sonnet" } }
    }));
    save_team(state, &team).expect("save a v2 team");
    let loaded = load_team(state).expect("load a v2 team").expect("a team");
    assert_eq!(loaded, team);
    assert_eq!(loaded.version, 2);
}

/// B2 (T73/T74 review): the capture mapping is pinned end to end — a v2 team WITH a reviewer and
/// WITHOUT a verifier must mint `run.created.steps = {verify:false, review:true}` and then spawn
/// exactly builder + reviewer. A transposed capture would spawn the wrong worker set and fail
/// both assertions.
#[test]
fn a_v2_subset_is_captured_on_run_created_and_shapes_the_spawns() {
    common::with_shared_env(|| async {
        let world = LoopWorld::new("pass", &[]);
        let actor = start_actor(&world, embedded_roles(), ActorOpts::default());
        let door = Door::over_state_dir(world.state_dir(), embedded_roles());
        let mut client = client_of(&door).await;

        let answer = client
            .call(
                "team.set",
                json!({
                    "team": {
                        "version": 2,
                        "name": "build and review, no verify",
                        "roles": {
                            "builder": { "provider": "claude", "model": "haiku" },
                            "reviewer": { "provider": "codex", "model": "gpt-5.5" }
                        }
                    }
                }),
            )
            .await
            .expect("team.set accepts a v2 subset");
        assert_eq!(answer["ok"], json!(true));

        let delegated = actor
            .handle
            .delegate(delegate_builder(loop_task("T74-subset")))
            .await
            .expect("delegate");
        let run = delegated.run_id;

        // The gate proves the whole chain ran; two spawns prove the verifier step was skipped.
        let events = poll_log(&world, run, "the integrate gate opened", |events| {
            events.iter().any(|e| {
                matches!(
                    &e.payload,
                    EventPayload::GateCreated { gate_kind, .. } if *gate_kind == GateKind::Integrate
                )
            })
        })
        .await;

        let captured = events
            .iter()
            .find_map(|e| match &e.payload {
                EventPayload::RunCreated { steps, .. } => Some(*steps),
                _ => None,
            })
            .expect("run.created");
        assert_eq!(
            captured,
            Some(RunSteps {
            security: false,
                verify: false,
                review: true
            }),
            "the v2 team's subset is captured verbatim — never transposed"
        );

        let roles: Vec<RoleName> = spawned(&events).into_iter().map(|s| s.0).collect();
        assert_eq!(
            roles,
            [RoleName::Builder, RoleName::Reviewer],
            "no verifier spawned for a team without one; the reviewer still ran"
        );

        quiesce(&actor.handle).await;
        actor.stop().await;
        door.stop().await.expect("the door stopped");
    });
}
