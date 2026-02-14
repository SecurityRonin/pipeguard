use anyhow::Context;
use colored::*;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;
use tracing::{debug, info, info_span};

use crate::cli::args::{resolve_rules_path, OutputFormat, EXIT_CLEAN, EXIT_ERROR, EXIT_THREAT};
use crate::config::settings::Config;
use crate::detection::pipeline::{DetectionPipeline, PipelineConfig};
use crate::detection::threat::ThreatLevel;

pub fn cmd_scan(
    rules: Option<PathBuf>,
    file: Option<&std::path::Path>,
    format: OutputFormat,
    quiet: bool,
) -> anyhow::Result<ExitCode> {
    // Resolve rules path: use provided, or search defaults
    let rules_path = match resolve_rules_path(rules) {
        Some(p) => p,
        None => {
            if !quiet {
                eprintln!(
                    "{}: No YARA rules found. Use --rules or install rules to a default location.",
                    "Error".red().bold()
                );
            }
            return Ok(ExitCode::from(EXIT_ERROR));
        }
    };

    let _span = info_span!("scan", rules_path = %rules_path.display(), input_source = if file.is_some() { "file" } else { "stdin" }).entered();

    // Load rules
    let pipeline = if rules_path.is_dir() {
        DetectionPipeline::from_rules_dir(&rules_path, PipelineConfig::default())?
    } else {
        let rules = std::fs::read_to_string(&rules_path)
            .with_context(|| format!("Failed to read rules file '{}'", rules_path.display()))?;
        DetectionPipeline::new(&rules, PipelineConfig::default())?
    };
    debug!(rule_count = pipeline.rule_count(), "Rules loaded");

    // Read content
    let content = match file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read input file '{}'", path.display()))?,
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read from stdin")?;
            buf
        }
    };
    debug!(
        content_bytes = content.len(),
        source = if file.is_some() { "file" } else { "stdin" },
        "Content read"
    );

    // Scan
    let start = Instant::now();
    let result = pipeline.analyze(&content)?;
    info!(
        threat_level = %result.threat_level(),
        match_count = result.match_count(),
        content_hash = %result.content_hash(),
        scan_duration_ms = start.elapsed().as_millis() as u64,
        "Scan complete"
    );

    // Check allowlist
    let config = Config::from_file(&Config::default_config_path()).unwrap_or_default();
    if config.is_allowlisted_hash(result.content_hash()) {
        if !quiet {
            println!("{} Allowlisted (hash match)", "✓".green());
        }
        return Ok(ExitCode::from(EXIT_CLEAN));
    }

    // Output (suppressed in quiet mode)
    if !quiet {
        match format {
            OutputFormat::Text => {
                if result.is_threat() {
                    let level_str = match result.threat_level() {
                        ThreatLevel::None => "None".green(),
                        ThreatLevel::Low => "Low".yellow(),
                        ThreatLevel::Medium => "Medium".truecolor(255, 165, 0),
                        ThreatLevel::High => "High".red().bold(),
                    };
                    println!("{} Threat Level: {}", "!".red().bold(), level_str);
                    println!();
                    println!("{}", result.report());
                    println!("Content Hash: {}", result.content_hash());
                } else {
                    println!("{} No threats detected.", "✓".green());
                    println!("Content Hash: {}", result.content_hash());
                }
            }
            OutputFormat::Json => {
                let matches: Vec<serde_json::Value> = result
                    .matches()
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "rule": m.rule_name(),
                            "severity": m.severity(),
                            "description": m.description(),
                        })
                    })
                    .collect();

                let json = serde_json::json!({
                    "threat_level": result.threat_level().to_string(),
                    "is_threat": result.is_threat(),
                    "match_count": result.match_count(),
                    "content_hash": result.content_hash(),
                    "matches": matches,
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
    }

    // Distinct exit codes: 0 = clean, 1 = threat, 2 = error
    Ok(ExitCode::from(if result.is_threat() {
        EXIT_THREAT
    } else {
        EXIT_CLEAN
    }))
}
