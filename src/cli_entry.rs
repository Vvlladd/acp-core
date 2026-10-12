//! Human terminal dialogue. The socket remains the only setup/approval authority.
use super::*;
use agent_control_plane::core::types::RunMode;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

pub(super) struct Setup {
    pub team: team::Team,
    pub audit_selection: Option<git::audit::Selection>,
}

struct Dialogue<R, W> {
    input: R,
    output: W,
}
impl<R: BufRead, W: Write> Dialogue<R, W> {
    fn ask(&mut self, label: &str, default: Option<&str>) -> anyhow::Result<String> {
        match default {
            Some(value) => write!(self.output, "{label} [{value}]: ")?,
            None => write!(self.output, "{label}: ")?,
        }
        self.output.flush()?;
        let mut answer = String::new();
        if self.input.read_line(&mut answer)? == 0 {
            bail!("setup ended before confirmation");
        }
        let answer = answer.trim();
        Ok(if answer.is_empty() {
            default.unwrap_or("").to_string()
        } else {
            answer.to_string()
        })
    }
    fn choose(&mut self, label: &str, count: usize, default: usize) -> anyhow::Result<usize> {
        loop {
            let answer = self.ask(label, Some(&(default + 1).to_string()))?;
            if let Ok(n) = answer.parse::<usize>() {
                if (1..=count).contains(&n) {
                    return Ok(n - 1);
                }
            }
            writeln!(self.output, "Choose a number from 1 to {count}.")?;
        }
    }
    fn reference(&mut self, label: &str) -> anyhow::Result<String> {
        loop {
            let answer = self.ask(label, None)?;
            if !answer.is_empty() && answer.len() <= 256 {
                return Ok(answer);
            }
            writeln!(self.output, "Enter a Git reference, up to 256 bytes.")?;
        }
    }
    fn assignment(
        &mut self,
        catalog: &team::RolesListResult,
        spec: &team::RolesListRole,
        label: &str,
        optional: bool,
        previous: Option<&team::Assignment>,
        default_off: bool,
    ) -> anyhow::Result<Option<team::Assignment>> {
        let mut choices = Vec::new();
        if optional {
            choices.push(None);
        }
        for (provider, entry) in &catalog.providers {
            if !entry.available {
                continue;
            }
            for model in &entry.models {
                if spec.models.contains(model) {
                    choices.push(Some(team::Assignment {
                        provider: *provider,
                        model: model.clone(),
                        effort: None,
                    }));
                }
            }
        }
        if choices.is_empty() {
            bail!("no installed provider is available for {label}; run acp doctor");
        }
        writeln!(self.output, "\n{label}:")?;
        for (index, choice) in choices.iter().enumerate() {
            writeln!(
                self.output,
                "  {}. {}",
                index + 1,
                assignment_label(choice.as_ref())
            )?;
        }
        let default = previous
            .and_then(|p| {
                choices.iter().position(|c| {
                    c.as_ref()
                        .is_some_and(|c| c.provider == p.provider && c.model == p.model)
                })
            })
            .unwrap_or_else(|| {
                if default_off {
                    0
                } else {
                    choices
                        .iter()
                        .position(|c| {
                            c.as_ref().is_some_and(|c| {
                                c.provider == spec.provider && c.model == spec.default_model
                            })
                        })
                        .unwrap_or(0)
                }
            });
        let index = self.choose("Choose", choices.len(), default)?;
        let Some(mut chosen) = choices[index].clone() else {
            return Ok(None);
        };
        // Revision 28: the chosen model's own list, not the provider's — gpt-5.5 takes no `max`.
        let efforts = catalog.providers[&chosen.provider].efforts_for(&chosen.model);
        if !efforts.is_empty() {
            writeln!(self.output, "Reasoning effort:\n  1. Provider default")?;
            for (index, effort) in efforts.iter().enumerate() {
                writeln!(self.output, "  {}. {effort}", index + 2)?;
            }
            let default = previous
                .filter(|p| p.provider == chosen.provider && p.model == chosen.model)
                .and_then(|p| p.effort)
                .and_then(|e| efforts.iter().position(|v| *v == e))
                .map_or(0, |n| n + 1);
            let n = self.choose("Choose effort", efforts.len() + 1, default)?;
            chosen.effort = n.checked_sub(1).map(|n| efforts[n]);
        }
        Ok(Some(chosen))
    }
    fn setup(
        &mut self,
        catalog: &team::RolesListResult,
        saved: Option<&team::Team>,
    ) -> anyhow::Result<Setup> {
        if catalog.human_setup_version < 1 {
            bail!("this running daemon needs an update for guided setup; update acp and restart it when its work finishes. The saved team has not changed");
        }
        let lead_spec = catalog.lead.as_ref().context(
            "this running daemon needs an update for guided lead selection; update acp and restart it when its work finishes")?;
        writeln!(self.output, "Choose who joins this task. Every worker can be Off.\nIn an existing Codex or Claude conversation, use the ACP skill to keep that conversation as lead.")?;
        let lead = self.assignment(
            catalog,
            lead_spec,
            "Lead",
            false,
            saved.and_then(|s| s.lead.as_ref()),
            false,
        )?;
        let mut roles = BTreeMap::new();
        for (key, label) in [
            ("builder", "Builder"),
            ("verifier", "Tests"),
            ("reviewer", "Code review"),
            ("security", "Security review"),
        ] {
            let Some(spec) = catalog.roles.iter().find(|r| r.name == key) else {
                writeln!(self.output, "{label}: unavailable in this daemon")?;
                continue;
            };
            let previous = saved.and_then(|s| s.roles.get(key));
            let default_off =
                previous.is_none() && (saved.is_some_and(|s| s.version >= 2) || key == "security");
            if let Some(assignment) =
                self.assignment(catalog, spec, label, true, previous, default_off)?
            {
                roles.insert(key.to_string(), assignment);
            }
        }
        let mode = if roles.contains_key("builder") {
            RunMode::Build
        } else if roles.is_empty() {
            RunMode::Plan
        } else {
            RunMode::Audit
        };
        let audit_selection = if mode == RunMode::Audit {
            writeln!(
                self.output,
                "\nAudit existing work. Checks inspect an isolated snapshot; no automatic commit."
            )?;
            let base_ref = self.reference("Comparison base (for example HEAD or main)")?;
            writeln!(self.output, "Input to inspect:\n  1. Current working tree (includes nonignored untracked files)\n  2. A committed revision")?;
            let target = match self.choose("Choose input", 2, 0)? {
                0 => git::audit::Target::WorkingTree {},
                _ => git::audit::Target::Revision {
                    revision: self.reference("Target revision")?,
                },
            };
            Some(git::audit::Selection { base_ref, target })
        } else {
            None
        };
        let team = team::Team {
            version: 3,
            mode: Some(mode),
            name: "Terminal team".into(),
            lead,
            roles,
        };
        writeln!(
            self.output,
            "\nTask: {}",
            match mode {
                RunMode::Build => "Build changes, then ask you to review before integration",
                RunMode::Plan => "Plan and discuss; no code changes",
                RunMode::Audit => "Audit selected existing work; no integration",
            }
        )?;
        writeln!(
            self.output,
            "Lead: {}",
            assignment_label(team.lead.as_ref())
        )?;
        for (key, label) in [
            ("builder", "Builder"),
            ("verifier", "Tests"),
            ("reviewer", "Code review"),
            ("security", "Security review"),
        ] {
            writeln!(
                self.output,
                "{label}: {}",
                assignment_label(team.roles.get(key))
            )?;
        }
        if let Some(selection) = &audit_selection {
            let target = match &selection.target {
                git::audit::Target::WorkingTree {} => "current working tree".into(),
                git::audit::Target::Revision { revision } => format!("revision {revision}"),
            };
            writeln!(
                self.output,
                "Audit input: {} → {target}",
                selection.base_ref
            )?;
        }
        Ok(Setup {
            team,
            audit_selection,
        })
    }
}
fn assignment_label(assignment: Option<&team::Assignment>) -> String {
    match assignment {
        None => "Off".into(),
        Some(a) => format!(
            "{}/{}{}",
            serde_json::to_value(a.provider).unwrap().as_str().unwrap(),
            a.model,
            a.effort.map_or_else(String::new, |e| format!(" ({e})"))
        ),
    }
}
pub(super) fn collect(
    catalog: &team::RolesListResult,
    saved: Option<&team::Team>,
) -> anyhow::Result<Setup> {
    Dialogue {
        input: io::stdin().lock(),
        output: io::stdout().lock(),
    }
    .setup(catalog, saved)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn catalog() -> team::RolesListResult {
        let roles = load_roles(None).unwrap();
        team::roles_list(
            &roles,
            &[(ProviderName::Claude, true), (ProviderName::Codex, true)].into(),
        )
    }
    #[test]
    fn every_worker_subset_has_the_right_mode_and_explicit_audit_input() {
        for mask in 0..16 {
            let input = format!(
                "1\n{}\n{}\n{}\n{}\nHEAD\n2\nmain\n", // Claude lead needs no effort choice
                if mask & 1 != 0 { 2 } else { 1 },
                if mask & 2 != 0 { 2 } else { 1 },
                if mask & 4 != 0 { 2 } else { 1 },
                if mask & 8 != 0 { 2 } else { 1 }
            );
            let mut dialogue = Dialogue {
                input: io::Cursor::new(input),
                output: Vec::new(),
            };
            let setup = dialogue.setup(&catalog(), None).unwrap();
            let expected = if mask & 1 != 0 {
                RunMode::Build
            } else if mask == 0 {
                RunMode::Plan
            } else {
                RunMode::Audit
            };
            assert_eq!(setup.team.mode, Some(expected));
            assert_eq!(setup.team.roles.len(), (mask as u32).count_ones() as usize);
            validate_team(&load_roles(None).unwrap(), &setup.team).unwrap();
            assert_eq!(setup.audit_selection.is_some(), expected == RunMode::Audit);
            if let Some(input) = setup.audit_selection {
                assert_eq!(input.base_ref, "HEAD");
                assert_eq!(
                    input.target,
                    git::audit::Target::Revision {
                        revision: "main".into()
                    }
                );
            }
        }
    }
    #[test]
    fn older_lead_catalog_is_refused_before_interview_or_team_change() {
        let mut old = serde_json::to_value(catalog()).unwrap();
        old.as_object_mut().unwrap().remove("humanSetupVersion");
        let old = serde_json::from_value(old).unwrap();
        let mut dialogue = Dialogue {
            input: io::Cursor::new(""),
            output: Vec::new(),
        };
        let error = dialogue.setup(&old, None).err().unwrap().to_string();
        assert!(error.contains("update acp and restart"), "{error}");
        assert!(error.contains("saved team has not changed"));
        assert!(dialogue.output.is_empty());
    }
    #[test]
    fn invalid_choice_retries_and_eof_never_confirms() {
        let mut dialogue = Dialogue {
            input: io::Cursor::new("0\nwrong\n3\n2\n"),
            output: Vec::new(),
        };
        assert_eq!(dialogue.choose("Choose", 2, 0).unwrap(), 1);
        assert!(dialogue.choose("Confirm", 2, 0).is_err());
    }
    /// The effort menu follows the chosen model, not the provider: gpt-5.5 never offers `max`,
    /// gpt-6-astra does. Lead choices are 4 claude models, then codex in catalog order.
    #[test]
    fn effort_choices_follow_the_chosen_model() {
        let run = |lead: &str, effort: &str| {
            let mut dialogue = Dialogue {
                input: io::Cursor::new(format!("{lead}\n{effort}\n1\n1\n1\n1\n")),
                output: Vec::new(),
            };
            let setup = dialogue.setup(&catalog(), None).unwrap();
            validate_team(&load_roles(None).unwrap(), &setup.team).unwrap();
            (String::from_utf8(dialogue.output).unwrap(), setup.team.lead.unwrap())
        };
        let (output, lead) = run("9", "5");
        assert_eq!((lead.model.as_str(), lead.effort), ("gpt-5.5", Some(team::Effort::Xhigh)));
        assert!(output.contains("  5. xhigh") && !output.contains("max"), "{output}");
        let (output, lead) = run("5", "6");
        assert_eq!((lead.model.as_str(), lead.effort), ("gpt-6-astra", Some(team::Effort::Max)));
        assert!(output.contains("  6. max"), "{output}");
    }
}
