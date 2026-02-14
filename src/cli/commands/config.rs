//! Config command: initialize and display PipeGuard configuration.

use anyhow::Context;
use std::process::ExitCode;
use tracing::debug;

use crate::cli::args::ConfigAction;
use crate::config::settings::Config;

/// Execute the `config` subcommand (init, show).
pub fn cmd_config(action: ConfigAction) -> anyhow::Result<ExitCode> {
    match action {
        ConfigAction::Init { path } => {
            let config_path = path.unwrap_or_else(Config::default_config_path);

            // Create parent directories
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create config directory '{}'", parent.display())
                })?;
            }

            let config = Config::default();
            let toml = config
                .to_toml()
                .context("Failed to serialize default config")?;
            std::fs::write(&config_path, toml).with_context(|| {
                format!("Failed to write config file '{}'", config_path.display())
            })?;

            debug!(path = %config_path.display(), "Config file created");
            println!("Created config at: {}", config_path.display());
            Ok(ExitCode::SUCCESS)
        }
        ConfigAction::Show => {
            let config_path = Config::default_config_path();
            if config_path.exists() {
                let content = std::fs::read_to_string(&config_path).with_context(|| {
                    format!("Failed to read config file '{}'", config_path.display())
                })?;
                println!("{}", content);
                debug!("Config displayed");
            } else {
                println!("No config file found at: {}", config_path.display());
                println!("Run 'pipeguard config init' to create one.");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
