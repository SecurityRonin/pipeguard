use anyhow::Context;
use colored::*;
use std::process::ExitCode;
use tracing::{info, debug};

use crate::cli::args::UpdateAction;
use crate::update::{UpdateManager, UpdateConfig};

pub fn cmd_update(action: UpdateAction) -> anyhow::Result<ExitCode> {
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
    let manager = UpdateManager::new(storage_path, config)
        .context("Failed to initialize update manager")?;

    match action {
        UpdateAction::Check { quiet, force, .. } => {
            // TODO: Implement force logic with timestamp checking
            let _ = force; // Silence unused warning for now

            match manager.check_for_updates()
                .context("Failed to check for updates")? {
                Some(version) => {
                    info!(version = %version, "Update available");
                    if !quiet {
                        println!("{} Update available: {}", "⚠️".yellow(), version);
                        println!("Run 'pipeguard update apply' to install.");
                    }
                    Ok(ExitCode::from(1)) // Exit code 1 indicates update available
                }
                None => {
                    debug!("No updates available");
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
            manager.apply_update(&version)
                .with_context(|| format!("Failed to apply update version '{}'", version))?;
            info!(version = %version, "Update applied");
            println!("{} Successfully activated version {}", "✓".green(), version);
            Ok(ExitCode::SUCCESS)
        }
        UpdateAction::Rollback { version, .. } => {
            println!("Rolling back to version: {}", version);
            manager.rollback(&version)
                .with_context(|| format!("Failed to rollback to version '{}'", version))?;
            info!(version = %version, "Rollback complete");
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
            manager.cleanup()
                .context("Failed to clean up old versions")?;
            debug!("Version cleanup complete");
            println!("{} Cleanup complete.", "✓".green());
            Ok(ExitCode::SUCCESS)
        }
    }
}
