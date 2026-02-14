use anyhow::Context;
use colored::*;
use std::process::ExitCode;
use tracing::info;

use crate::cli::args::RulesAction;
use crate::detection::pipeline::{DetectionPipeline, PipelineConfig};

pub fn cmd_rules(action: RulesAction) -> anyhow::Result<ExitCode> {
    match action {
        RulesAction::List => {
            // For now, show that no built-in rules are loaded
            // In a full implementation, we'd list rules from a default location
            println!("Built-in rules:");
            println!("  No rules loaded. Use --rules to specify a rules file.");
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
