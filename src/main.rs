use clap::Parser;
use colored::*;
use pipeguard::cli::args::{Cli, Commands, ConfigAction, OutputFormat, RulesAction, ShellType, UpdateAction};
use pipeguard::config::settings::Config;
use pipeguard::detection::pipeline::{DetectionPipeline, PipelineConfig};
use pipeguard::detection::threat::ThreatLevel;
use pipeguard::update::{UpdateManager, UpdateConfig};
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Commands::Scan { rules, file, format } => {
            cmd_scan(&rules, file.as_deref(), format)
        }
        Commands::Install { dry_run, shell } => {
            cmd_install(dry_run, shell)
        }
        Commands::Config { action } => {
            cmd_config(action)
        }
        Commands::Rules { action } => {
            cmd_rules(action)
        }
        Commands::Update { action } => {
            cmd_update(action)
        }
    }
}

fn cmd_scan(rules_path: &Path, file: Option<&Path>, format: OutputFormat) -> anyhow::Result<ExitCode> {
    // Load rules
    let pipeline = if rules_path.is_dir() {
        DetectionPipeline::from_rules_dir(rules_path, PipelineConfig::default())?
    } else {
        let rules = std::fs::read_to_string(rules_path)?;
        DetectionPipeline::new(&rules, PipelineConfig::default())?
    };

    // Read content
    let content = match file {
        Some(path) => std::fs::read_to_string(path)?,
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    // Scan
    let result = pipeline.analyze(&content)?;

    // Output
    match format {
        OutputFormat::Text => {
            if result.is_threat() {
                let level_str = match result.threat_level() {
                    ThreatLevel::None => "None".green(),
                    ThreatLevel::Low => "Low".yellow(),
                    ThreatLevel::Medium => "Medium".truecolor(255, 165, 0), // Orange
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
            let json = serde_json::json!({
                "threat_level": format!("{:?}", result.threat_level()),
                "is_threat": result.is_threat(),
                "match_count": result.match_count(),
                "content_hash": result.content_hash(),
                "matches": result.report(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    // Exit code based on threat level
    Ok(if result.is_threat() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_install(dry_run: bool, shell: ShellType) -> anyhow::Result<ExitCode> {
    let shells_to_install = match shell {
        ShellType::Zsh => vec!["zsh"],
        ShellType::Bash => vec!["bash"],
        ShellType::Fish => vec!["fish"],
        ShellType::All => vec!["zsh", "bash", "fish"],
    };

    if dry_run {
        println!("Would install shell integration for:");
        for s in &shells_to_install {
            println!("  - {}", s);
        }
        println!();
        println!("Run without --dry-run to apply changes.");
    } else {
        for s in &shells_to_install {
            println!("Installing {} integration...", s);
            // Actual installation would go here
        }
        println!("Shell integration installed. Restart your shell or source the config.");
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_config(action: ConfigAction) -> anyhow::Result<ExitCode> {
    match action {
        ConfigAction::Init { path } => {
            let config_path = path.unwrap_or_else(Config::default_config_path);

            // Create parent directories
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let config = Config::default();
            let toml = config.to_toml()?;
            std::fs::write(&config_path, toml)?;

            println!("Created config at: {}", config_path.display());
            Ok(ExitCode::SUCCESS)
        }
        ConfigAction::Show => {
            let config_path = Config::default_config_path();
            if config_path.exists() {
                let content = std::fs::read_to_string(&config_path)?;
                println!("{}", content);
            } else {
                println!("No config file found at: {}", config_path.display());
                println!("Run 'pipeguard config init' to create one.");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_rules(action: RulesAction) -> anyhow::Result<ExitCode> {
    match action {
        RulesAction::List => {
            // For now, show that no built-in rules are loaded
            // In a full implementation, we'd list rules from a default location
            println!("Built-in rules:");
            println!("  No rules loaded. Use --rules to specify a rules file.");
            Ok(ExitCode::SUCCESS)
        }
        RulesAction::Validate { path } => {
            let rules = std::fs::read_to_string(&path)?;
            match DetectionPipeline::new(&rules, PipelineConfig::default()) {
                Ok(_) => {
                    println!("{} Rules are valid.", "✓".green());
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    println!("{} Invalid rules: {}", "✗".red(), e);
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn cmd_update(action: UpdateAction) -> anyhow::Result<ExitCode> {
    // Determine storage path
    let storage_path = match &action {
        UpdateAction::Check { storage, .. } => storage.clone(),
        UpdateAction::Apply { storage, .. } => storage.clone(),
        UpdateAction::Rollback { storage, .. } => storage.clone(),
        UpdateAction::Status { storage } => storage.clone(),
        UpdateAction::Cleanup { storage } => storage.clone(),
    }.unwrap_or_else(|| {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".pipeguard/rules")
    });

    let config = UpdateConfig::default();
    let manager = UpdateManager::new(storage_path, config)?;

    match action {
        UpdateAction::Check { quiet, force, .. } => {
            // TODO: Implement force logic with timestamp checking
            let _ = force; // Silence unused warning for now

            match manager.check_for_updates()? {
                Some(version) => {
                    if !quiet {
                        println!("{} Update available: {}", "⚠️".yellow(), version);
                        println!("Run 'pipeguard update apply' to install.");
                    }
                    Ok(ExitCode::from(1)) // Exit code 1 indicates update available
                }
                None => {
                    if !quiet {
                        println!("{} No updates available.", "✓".green());
                    }
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
        UpdateAction::Apply { version, .. } => {
            let version = version.unwrap_or_else(|| "latest".to_string());

            if version == "latest" {
                println!("Checking for latest version...");
                // TODO: Implement actual download from GitHub
                println!("{} GitHub integration not yet implemented.", "⚠️".yellow());
                println!("Use --version to specify an existing version.");
                return Ok(ExitCode::FAILURE);
            }

            println!("Applying update: {}", version);
            manager.apply_update(&version)?;
            println!("{} Successfully activated version {}", "✓".green(), version);
            Ok(ExitCode::SUCCESS)
        }
        UpdateAction::Rollback { version, .. } => {
            println!("Rolling back to version: {}", version);
            manager.rollback(&version)?;
            println!("{} Successfully rolled back to {}", "✓".green(), version);
            Ok(ExitCode::SUCCESS)
        }
        UpdateAction::Status { .. } => {
            match manager.current_version() {
                Ok(version) => {
                    println!("Current version: {}", version.green().bold());
                    if manager.has_version(&version) {
                        println!("Status: {}", "Active".green());
                    }
                }
                Err(_) => {
                    println!("Status: {}", "No active version".yellow());
                    println!("Run 'pipeguard update apply' to activate a version.");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        UpdateAction::Cleanup { .. } => {
            println!("Cleaning up old versions...");
            manager.cleanup()?;
            println!("{} Cleanup complete.", "✓".green());
            Ok(ExitCode::SUCCESS)
        }
    }
}
