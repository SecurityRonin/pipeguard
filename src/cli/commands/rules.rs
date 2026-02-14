//! Rules command: list, validate, and inspect YARA rule files.

use anyhow::Context;
use colored::*;
use std::process::ExitCode;
use tracing::info;

use crate::cli::args::{resolve_rules_path, RulesAction};
use crate::config::settings::Config;
use crate::detection::pipeline::{DetectionPipeline, PipelineConfig};

/// Execute the `rules` subcommand (list, validate, info).
pub fn cmd_rules(action: RulesAction) -> anyhow::Result<ExitCode> {
    match action {
        RulesAction::List { rules } => {
            let config = Config::from_file(&Config::default_config_path()).unwrap_or_default();
            let rules_path =
                match resolve_rules_path(rules, config.rules.custom_rules_path.as_deref()) {
                    Some(p) => p,
                    None => {
                        println!("No rules found.");
                        println!(
                        "Use {} to specify a rules file or install rules to a default location.",
                        "--rules".bold()
                    );
                        return Ok(ExitCode::SUCCESS);
                    }
                };

            let content = if rules_path.is_dir() {
                let mut combined = String::new();
                for entry in std::fs::read_dir(&rules_path).with_context(|| {
                    format!("Failed to read rules dir '{}'", rules_path.display())
                })? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("yar") {
                        combined.push_str(
                            &std::fs::read_to_string(&path)
                                .with_context(|| format!("Failed to read '{}'", path.display()))?,
                        );
                        combined.push('\n');
                    }
                }
                combined
            } else {
                std::fs::read_to_string(&rules_path).with_context(|| {
                    format!("Failed to read rules file '{}'", rules_path.display())
                })?
            };

            // Collect rules with their severity metadata
            let mut rules_found: Vec<(String, Option<String>)> = Vec::new();
            let mut in_meta = false;
            let mut current_name: Option<String> = None;
            let mut current_severity: Option<String> = None;

            for line in content.lines() {
                let trimmed = line.trim();

                if trimmed.starts_with("rule ") {
                    // Save previous rule if any
                    if let Some(name) = current_name.take() {
                        rules_found.push((name, current_severity.take()));
                    }
                    current_name = trimmed
                        .strip_prefix("rule ")
                        .and_then(|s| s.split_whitespace().next())
                        .map(|s| s.to_string());
                    current_severity = None;
                    in_meta = false;
                } else if trimmed == "meta:" {
                    in_meta = true;
                } else if trimmed.starts_with("strings:")
                    || trimmed.starts_with("condition:")
                    || trimmed == "}"
                {
                    in_meta = false;
                } else if in_meta {
                    if let Some((key, value)) = trimmed.split_once('=') {
                        if key.trim() == "severity" {
                            current_severity =
                                Some(value.trim().trim_matches('"').trim().to_string());
                        }
                    }
                }
            }
            // Don't forget the last rule
            if let Some(name) = current_name.take() {
                rules_found.push((name, current_severity.take()));
            }

            for (name, severity) in &rules_found {
                match severity {
                    Some(sev) => println!("  {} (severity: {})", name.cyan(), sev),
                    None => println!("  {}", name.cyan()),
                }
            }

            let count = rules_found.len();
            info!(count = count, path = %rules_path.display(), "Rules listed");
            println!();
            println!("{} rule(s) found in {}", count, rules_path.display());
            Ok(ExitCode::SUCCESS)
        }
        RulesAction::Validate { path } => {
            let rules = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read rules file '{}'", path.display()))?;
            match DetectionPipeline::new(&rules, PipelineConfig::default()) {
                Ok(_) => {
                    info!(path = %path.display(), "Rules validated successfully");
                    println!("{} Rules are valid.", "✓".green());
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    info!(path = %path.display(), error = %e, "Rules validation failed");
                    println!("{} Invalid rules: {}", "✗".red(), e);
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        RulesAction::Info { path } => {
            info!(path = %path.display(), "Showing rule info");
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read rules file '{}'", path.display()))?;

            // Parse rule metadata from YARA source
            let mut in_meta = false;
            let mut current_rule: Option<String> = None;

            for line in content.lines() {
                let trimmed = line.trim();

                if trimmed.starts_with("rule ") {
                    let name = trimmed
                        .strip_prefix("rule ")
                        .and_then(|s| s.split_whitespace().next())
                        .unwrap_or("unknown");
                    current_rule = Some(name.to_string());
                    println!("{}", name.cyan().bold());
                    in_meta = false;
                } else if trimmed == "meta:" {
                    in_meta = true;
                } else if in_meta && trimmed.starts_with("strings:")
                    || trimmed.starts_with("condition:")
                {
                    in_meta = false;
                } else if in_meta && current_rule.is_some() {
                    if let Some((key, value)) = trimmed.split_once('=') {
                        let key = key.trim();
                        let value = value.trim().trim_matches('"');
                        println!("  {}: {}", key, value);
                    }
                }

                if trimmed == "}" && current_rule.is_some() {
                    current_rule = None;
                    println!();
                }
            }

            Ok(ExitCode::SUCCESS)
        }
    }
}
