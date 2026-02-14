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
    }
}
