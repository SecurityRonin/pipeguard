use clap::{CommandFactory, Parser};
use colored::*;
use pipeguard::cli::args::{Cli, ColorMode, Commands, CompletionShell, EXIT_ERROR};
use pipeguard::cli::commands::{cmd_config, cmd_install, cmd_rules, cmd_scan, cmd_update};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Handle color mode (respects NO_COLOR env var)
    match cli.color {
        ColorMode::Always => colored::control::set_override(true),
        ColorMode::Never => colored::control::set_override(false),
        ColorMode::Auto => {
            if std::env::var_os("NO_COLOR").is_some() {
                colored::control::set_override(false);
            }
        }
    }

    // Initialize structured logging before any command runs.
    // log_level/log_format are consumed here; only command is forwarded.
    if let Err(e) = pipeguard::logging::init(cli.log_level.into(), cli.log_format) {
        eprintln!(
            "{}: Failed to initialize logging: {}",
            "Error".red().bold(),
            e
        );
        return ExitCode::FAILURE;
    }

    match run(cli.command) {
        Ok(exit_code) => exit_code,
        Err(e) => {
            tracing::error!(error = %e, "Command failed");
            eprintln!("{}: {}", "Error".red().bold(), e);
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(command: Commands) -> anyhow::Result<ExitCode> {
    match command {
        Commands::Scan {
            rules,
            file,
            format,
            quiet,
        } => cmd_scan(rules, file.as_deref(), format, quiet),
        Commands::Install { dry_run, shell } => cmd_install(dry_run, shell),
        Commands::Config { action } => cmd_config(action),
        Commands::Rules { action } => cmd_rules(action),
        Commands::Update { action } => cmd_update(action),
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut cmd,
                        "pipeguard",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut cmd,
                        "pipeguard",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut cmd,
                        "pipeguard",
                        &mut std::io::stdout(),
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
