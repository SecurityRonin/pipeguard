use clap::Parser;
use colored::*;
use pipeguard::cli::args::{Cli, Commands};
use pipeguard::cli::commands::{cmd_scan, cmd_install, cmd_config, cmd_rules, cmd_update};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize structured logging before any command runs.
    // log_level/log_format are consumed here; only command is forwarded.
    if let Err(e) = pipeguard::logging::init(cli.log_level.into(), cli.log_format) {
        eprintln!("{}: Failed to initialize logging: {}", "Error".red().bold(), e);
        return ExitCode::FAILURE;
    }

    match run(cli.command) {
        Ok(exit_code) => exit_code,
        Err(e) => {
            tracing::error!(error = %e, "Command failed");
            eprintln!("{}: {}", "Error".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

fn run(command: Commands) -> anyhow::Result<ExitCode> {
    match command {
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
