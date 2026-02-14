//! Update command: check, download, apply, rollback, and manage rule updates.

use anyhow::Context;
use colored::*;
use std::process::ExitCode;
use tracing::{debug, info};

use crate::cli::args::{UpdateAction, EXIT_UPDATE_AVAILABLE};
use crate::update::{UpdateConfig, UpdateManager};

/// Execute the `update` subcommand (check, apply, rollback, status, cleanup).
pub fn cmd_update(action: UpdateAction) -> anyhow::Result<ExitCode> {
    // Determine storage path
    let storage_path = match &action {
        UpdateAction::Check { storage, .. } => storage.clone(),
        UpdateAction::Apply { storage, .. } => storage.clone(),
        UpdateAction::Rollback { storage, .. } => storage.clone(),
        UpdateAction::Status { storage } => storage.clone(),
        UpdateAction::Cleanup { storage } => storage.clone(),
    }
    .unwrap_or_else(|| {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".pipeguard/rules")
    });

    let config = UpdateConfig::default();
    let manager =
        UpdateManager::new(storage_path, config).context("Failed to initialize update manager")?;

    match action {
        UpdateAction::Check { quiet, force, .. } => {
            if !force && !manager.should_check() {
                debug!("Skipping update check (checked recently)");
                if !quiet {
                    println!(
                        "{} Recently checked. Use --force to check now.",
                        "✓".green()
                    );
                }
                return Ok(ExitCode::SUCCESS);
            }

            manager
                .record_check()
                .context("Failed to record check timestamp")?;

            match manager
                .check_for_updates()
                .context("Failed to check for updates")?
            {
                Some(version) => {
                    info!(version = %version, "Update available");
                    if !quiet {
                        println!("{} Update available: {}", "⚠️".yellow(), version);
                        println!("Run 'pipeguard update apply' to install.");
                    }
                    Ok(ExitCode::from(EXIT_UPDATE_AVAILABLE))
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
            let version = match version {
                Some(v) => v,
                None => {
                    println!("Checking for latest version...");
                    match manager
                        .check_for_updates()
                        .context("Failed to check for updates")?
                    {
                        Some(v) => {
                            println!("Found version: {}", v);
                            v
                        }
                        None => {
                            println!("{} Already up to date.", "✓".green());
                            return Ok(ExitCode::SUCCESS);
                        }
                    }
                }
            };

            // If the version is already downloaded and verified, just activate it
            if manager.has_version(&version) {
                println!("Activating existing version: {}", version);
                manager
                    .apply_update(&version)
                    .with_context(|| format!("Failed to apply update version '{}'", version))?;
            } else {
                println!("Downloading version {}...", version);
                manager.process_update(&version).with_context(|| {
                    format!("Failed to download and apply version '{}'", version)
                })?;

                // If process_update didn't auto-apply, apply now
                manager
                    .apply_update(&version)
                    .with_context(|| format!("Failed to activate version '{}'", version))?;
            }

            info!(version = %version, "Update applied");
            println!("{} Successfully activated version {}", "✓".green(), version);
            Ok(ExitCode::SUCCESS)
        }
        UpdateAction::Rollback { version, .. } => {
            println!("Rolling back to version: {}", version);
            manager
                .rollback(&version)
                .with_context(|| format!("Failed to rollback to version '{}'", version))?;
            info!(version = %version, "Rollback complete");
            println!("{} Successfully rolled back to {}", "✓".green(), version);
            Ok(ExitCode::SUCCESS)
        }
        UpdateAction::Status { .. } => {
            match manager.current_version()? {
                Some(version) => {
                    println!("Current version: {}", version.green().bold());
                    if manager.has_version(&version) {
                        println!("Status: {}", "Active".green());
                    }
                }
                None => {
                    println!("Status: {}", "No active version".yellow());
                    println!("Run 'pipeguard update apply' to activate a version.");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        UpdateAction::Cleanup { .. } => {
            println!("Cleaning up old versions...");
            manager
                .cleanup()
                .context("Failed to clean up old versions")?;
            debug!("Version cleanup complete");
            println!("{} Cleanup complete.", "✓".green());
            Ok(ExitCode::SUCCESS)
        }
    }
}
