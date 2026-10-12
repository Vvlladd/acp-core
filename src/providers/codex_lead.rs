//! Codex 0.153.0 coordination profile. See the zero-token probes in the Sep 5 research record.
use super::{base_env, path_arg, SpawnPlan, SpawnRequest};
use crate::core::policy::{PolicyCode, PolicyError};
use crate::core::types::RunId;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const REQUIRED_VERSION: &str = "codex-cli 0.153.0";
const CATALOG: &str = "lead-model-catalog.json";
const INSTRUCTIONS: &str = "lead-instructions.md";
const TOOLS: &[&str] = &[
    "delegate",
    "submit_plan",
    "audit_existing",
    "send_message",
    "await_result",
    "get_status",
    "cancel",
    "request_human_gate",
    "resolve_gate",
];
const DISABLED_FEATURES: &[&str] = &[
    "hooks",
    "shell_tool",
    "sleep_tool",
    "unified_exec",
    "multi_agent",
    "multi_agent_v2",
    "apps",
    "plugins",
    "code_mode",
    "code_mode_only",
    "js_repl",
    "view_image",
    "image_generation",
    "remote_models",
    "request_permissions_tool",
    "tool_search",
    "tool_suggest",
    "current_time_reminder",
    "token_budget",
    "deferred_executor",
    "goals",
    "memories",
    "remote_plugin",
    "recommended_plugins",
];

/// The models a Codex lead may run, each with the reasoning levels it takes — the embedded
/// `roles.json` catalog restated where the chokepoint can see it without a config (a test pins the
/// two equal). Codex 0.153.0 accepts any non-empty effort string at config time and only the API
/// refuses a pair (report 31), so this table is what actually bounds the profile. `ultra` is absent
/// on purpose: it makes Codex delegate to its own sub-agents.
pub(crate) const MODELS: &[(&str, &[&str])] = &[
    ("gpt-6-astra", &["low", "medium", "high", "xhigh", "max"]),
    ("gpt-5.6-sol", &["low", "medium", "high", "xhigh", "max"]),
    ("gpt-5.6-terra", &["low", "medium", "high", "xhigh", "max"]),
    ("gpt-5.6-luna", &["low", "medium", "high", "xhigh", "max"]),
    ("gpt-5.5", &["low", "medium", "high", "xhigh"]),
    ("gpt-5.3-codex-spark", &["low", "medium", "high", "xhigh"]),
];

fn levels(model: &str) -> Option<&'static [&'static str]> {
    MODELS.iter().find(|(m, _)| *m == model).map(|(_, l)| *l)
}

/// `supported_reasoning_levels` for the daemon-owned catalog: the model's own levels, so the
/// CLI advertises `max` only where the model takes it. An unknown model gets none — `check_plan`
/// refuses it before anything is spawned.
fn reasoning_levels(model: &str) -> Vec<Value> {
    levels(model)
        .unwrap_or(&[])
        .iter()
        .map(|effort| {
            let description = match *effort {
                "low" => "Low",
                "medium" => "Medium",
                "high" => "High",
                "xhigh" => "Extra high",
                "max" => "Maximum",
                other => other,
            };
            json!({"effort": effort, "description": description})
        })
        .collect()
}

fn model_catalog(model: &str, body: &str) -> String {
    json!({"models":[{"slug":model,"display_name":model,"description":"ACP coordination profile",
        "supported_reasoning_levels":reasoning_levels(model),"shell_type":"disabled","visibility":"list","supported_in_api":true,
        "priority":1,"support_verbosity":false,"apply_patch_tool_type":null,
        "truncation_policy":{"mode":"bytes","limit":10000},"experimental_supported_tools":[],
        "include_apps_usage_instructions":false,"include_plugin_usage_instructions":false,
        "include_skills_usage_instructions":false,"node_repl_disabled":true,"multi_agent_version":"disabled",
        "tool_mode":"direct","context_window":128000,"base_instructions":body}]}).to_string()
}

/// JSON string encoding is also a valid TOML basic string. Keys here are adapter-owned identifiers.
fn toml(value: &Value) -> String {
    match value {
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{k}={}", toml(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(toml).collect::<Vec<_>>().join(",")
        ),
        _ => value.to_string(),
    }
}

fn argv(
    model: &str,
    effort: &str,
    repo: &Path,
    state: &Path,
    dir: &Path,
    run: RunId,
    session: Option<&str>,
) -> Vec<String> {
    let mut args = vec!["exec".into()];
    if session.is_some() {
        args.push("resume".into());
    }
    args.extend([
        "--json".into(),
        "--strict-config".into(),
        "--ignore-user-config".into(),
        "-m".into(),
        model.into(),
    ]);
    if session.is_none() {
        args.extend(["-s".into(), "read-only".into()]);
    }
    let mut config = serde_json::Map::new();
    config.insert("approval_policy".into(), json!("never"));
    config.insert("notify".into(), json!([]));
    config.insert("model_provider".into(), json!("openai"));
    config.insert("model_providers".into(), json!({}));
    // 0.153.0 filters an empty override to None, preserving the official API/ChatGPT route
    // selected by auth mode. A fixed API URL would break ChatGPT-authenticated leads.
    config.insert("openai_base_url".into(), json!(""));
    config.insert("sandbox_mode".into(), json!("read-only"));
    config.insert("model_catalog_json".into(), json!(dir.join(CATALOG)));
    config.insert(
        "model_instructions_file".into(),
        json!(dir.join(INSTRUCTIONS)),
    );
    config.insert("model_reasoning_effort".into(), json!(effort));
    config.insert("web_search".into(), json!("disabled"));
    config.insert("tools.update_plan".into(), json!({"enabled":false}));
    config.insert(
        "tools.experimental_request_user_input".into(),
        json!({"enabled":false}),
    );
    config.insert("agents.enabled".into(), json!(false));
    config.insert("analytics".into(), json!({"enabled":false}));
    config.insert("feedback".into(), json!({"enabled":false}));
    config.insert("features.skip_host_skill_discovery".into(), json!(true));
    config.insert("project_doc_max_bytes".into(), json!(0));
    config.insert("skills.max_context_tokens".into(), json!(1));
    for feature in DISABLED_FEATURES {
        config.insert(format!("features.{feature}"), json!(false));
    }
    let mut env = serde_json::Map::from_iter([
        ("ACP_STATE_DIR".into(), json!(state)),
        ("ACP_LEAD_RUN_ID".into(), json!(run.to_string())),
    ]);
    if let Some(roles) = super::super::proxy_roles_file() {
        env.insert("ACP_ROLES_FILE".into(), json!(roles));
    }
    let command = std::env::current_exe().ok().filter(|p| p.is_absolute());
    // Permission to invoke these existing agent operations does not approve an ACP human gate.
    // No server-wide auto approval: unknown tools remain unexposed and prompt by default.
    let tool_policy = TOOLS.iter().map(|name| ((*name).to_string(), json!({"approval_mode":"approve"})))
        .collect::<serde_json::Map<_, _>>();
    config.insert("mcp_servers".into(), json!({"acp":{"command":command,
        "args":["mcp-proxy","--repo",repo],"env":env,"enabled":true,"required":true,
        "enabled_tools":TOOLS,"default_tools_approval_mode":"prompt","tools":tool_policy}}));
    for (key, value) in config {
        args.extend(["-c".into(), format!("{key}={}", toml(&value))]);
    }
    args.extend(["-o".into(), path_arg(&dir.join("last-message.txt"))]);
    if let Some(session) = session {
        args.push(session.into());
    }
    args
}

pub(super) fn plan(req: &SpawnRequest<'_>, resume: bool) -> SpawnPlan {
    let run = req.lead_run_id.unwrap_or_else(|| RunId::from_uuid(uuid::Uuid::nil()));
    let effort = req.effort.map_or("medium", |e| e.as_str());
    let mut args = argv(
        req.model,
        effort,
        req.cwd,
        req.state_dir,
        req.attempt_dir,
        run,
        if resume { req.session_id } else { None },
    );
    args.push(req.prompt.into());
    SpawnPlan {
        required_version: Some(REQUIRED_VERSION.into()),
        file: PathBuf::from("codex"),
        argv: args,
        cwd: req.cwd.into(),
        env: base_env(),
        write_files: vec![
            (
                req.attempt_dir.join(CATALOG),
                model_catalog(req.model, req.role_prompt),
            ),
            (req.attempt_dir.join(INSTRUCTIONS), req.role_prompt.into()),
        ],
    }
}

/// Reconstruct the entire profile at the spawn chokepoint; duplicate/extra flags, files, broader
/// tools, wrong repo/instance attribution and missing version pins are refused before spawning.
pub(crate) fn check_plan(
    plan: &SpawnPlan,
    repo: &Path,
    state: &Path,
    run: Option<RunId>,
) -> Result<(), PolicyError> {
    let refused = || {
        PolicyError::new(
            PolicyCode::UnsafeArgv,
            "the Codex lead requires the exact measured ACP-only coordination profile",
        )
    };
    let run = run.filter(|id| !id.as_uuid().is_nil()).ok_or_else(refused)?;
    let model = plan
        .argv
        .windows(2)
        .find(|p| p[0] == "-m")
        .map(|p| p[1].as_str())
        .ok_or_else(refused)?;
    let levels = levels(model).ok_or_else(refused)?;
    let instructions = plan
        .write_files
        .iter()
        .find(|(p, _)| p.file_name().is_some_and(|n| n == INSTRUCTIONS))
        .ok_or_else(refused)?;
    let dir = instructions.0.parent().ok_or_else(refused)?;
    let effort = plan
        .argv
        .iter()
        .find_map(|v| v.strip_prefix("model_reasoning_effort="))
        .and_then(|s| serde_json::from_str::<String>(s).ok())
        .ok_or_else(refused)?;
    if !levels.contains(&effort.as_str()) {
        return Err(refused());
    }
    let prompt = plan.argv.last().ok_or_else(refused)?;
    let session = if plan.argv.get(1).is_some_and(|s| s == "resume") {
        Some(
            plan.argv
                .get(plan.argv.len().saturating_sub(2))
                .ok_or_else(refused)?
                .as_str(),
        )
    } else {
        None
    };
    if session.is_some_and(|s| s.starts_with('-') || s.is_empty() || s.len() > 128) {
        return Err(refused());
    }
    let mut expected = argv(model, &effort, repo, state, dir, run, session);
    expected.push(prompt.clone());
    if plan.required_version.as_deref() != Some(REQUIRED_VERSION)
        || plan.cwd != repo
        || plan.argv != expected
        || plan.write_files
            != vec![
                (dir.join(CATALOG), model_catalog(model, &instructions.1)),
                (dir.join(INSTRUCTIONS), instructions.1.clone()),
            ]
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::team::Effort;
    use crate::core::types::{ProviderName, RoleName, RoleSpec, SchemaName};
    use crate::roles::loader::load_roles;

    fn lead_spec() -> RoleSpec {
        RoleSpec {
            role: RoleName::Lead,
            provider: ProviderName::Codex,
            models: Vec::new(),
            default_model: "gpt-5.5".into(),
            writes: false,
            prompt_file: None,
            prompt_sha256: None,
            description: None,
            tools: None,
            sandbox_mode: None,
            max_turns: 100,
            spawn_budget_usd: 2.0,
            result_schema: SchemaName::FreeText,
            allowed_delegations: Vec::new(),
        }
    }

    /// Builds the fresh plan for `model`/`effort` and runs it through the chokepoint.
    fn checked(model: &str, effort: Option<Effort>) -> Result<(), PolicyError> {
        let spec = lead_spec();
        let schema = json!({});
        let repo = Path::new("/repo");
        let state = Path::new("/repo/.acp");
        let attempt = Path::new("/repo/.acp/attempts/a1");
        let run = RunId::from_uuid(uuid::Uuid::from_u128(7));
        let req = SpawnRequest {
            role: &spec,
            model,
            prompt: "hi",
            role_prompt: "body",
            cwd: repo,
            attempt_dir: attempt,
            state_dir: state,
            lead_run_id: Some(run),
            schema: ("free-text", &schema),
            max_turns: 100,
            spawn_budget_usd: 2.0,
            sandbox: None,
            session_id: None,
            effort,
        };
        check_plan(&plan(&req, false), repo, state, Some(run))
    }

    fn levels(model: &str) -> Vec<String> {
        let catalog: Value = serde_json::from_str(&model_catalog(model, "body")).expect("json");
        catalog["models"][0]["supported_reasoning_levels"]
            .as_array()
            .expect("levels")
            .iter()
            .map(|level| level["effort"].as_str().expect("effort").to_owned())
            .collect()
    }

    /// The daemon-owned catalog advertises each model's own levels — `max` only where the model
    /// takes it — because that file is what Codex validates the configured effort against.
    #[test]
    fn the_catalog_lists_each_models_own_levels() {
        assert_eq!(levels("gpt-5.5"), ["low", "medium", "high", "xhigh"]);
        assert_eq!(levels("gpt-6-astra"), ["low", "medium", "high", "xhigh", "max"]);
    }

    #[test]
    fn the_chokepoint_binds_the_effort_to_the_models_own_levels() {
        assert!(checked("gpt-6-astra", Some(Effort::Max)).is_ok());
        assert!(checked("gpt-5.6-luna", None).is_ok());
        assert!(checked("gpt-5.5", Some(Effort::High)).is_ok());
        assert!(checked("gpt-5.5", Some(Effort::Max)).is_err());
        assert!(checked("gpt-9", Some(Effort::Low)).is_err());
    }

    /// One table, two owners: the adapter's models and levels are exactly the embedded catalog's,
    /// so `roles.json` cannot offer a Codex lead the chokepoint would then refuse.
    #[test]
    fn the_adapter_table_is_the_embedded_codex_catalog() {
        let cfg = load_roles(None).expect("embedded roles config");
        let codex = &cfg.providers[&ProviderName::Codex];
        assert_eq!(
            MODELS.iter().map(|(model, _)| *model).collect::<Vec<_>>(),
            codex.models
        );
        for (model, table) in MODELS {
            let catalog: Vec<&str> = codex.efforts_for(model).iter().map(|e| e.as_str()).collect();
            assert_eq!(*table, catalog.as_slice(), "{model}");
        }
    }
}
