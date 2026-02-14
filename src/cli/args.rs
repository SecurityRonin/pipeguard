//! Command-line argument parsing.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// PipeGuard - Defending against curl|bash attacks
#[derive(Parser, Debug)]
#[command(name = "pipeguard")]
#[command(author, version, about, long_about = None)]
#[command(about = "PipeGuard - Defending against curl|bash attacks through multi-layer shell interception")]
pub struct Cli {
    /// Logging verbosity level
    #[arg(long, global = true, default_value = "warn")]
    pub log_level: LogLevel,

    /// Logging output format
    #[arg(long, global = true, default_value = "pretty")]
    pub log_format: crate::logging::LogFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan content for threats
    Scan {
        /// Path to YARA rules file or directory
        #[arg(short, long)]
        rules: PathBuf,

        /// File to scan (reads from stdin if not provided)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Output format: text, json
        #[arg(short = 'F', long, default_value = "text")]
        format: OutputFormat,
    },

    /// Install shell integration
    Install {
        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,

        /// Shell to install for: zsh, bash, fish, all
        #[arg(short, long, default_value = "all")]
        shell: ShellType,
    },

    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Manage YARA rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Manage automatic updates
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Initialize default configuration
    Init {
        /// Path to create config file
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Show current configuration
    Show,
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List available rules
    List,

    /// Validate rules syntax
    Validate {
        /// Path to rules file or directory
        #[arg(short, long)]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum UpdateAction {
    /// Check for available updates
    Check {
        /// Don't print output, only set exit code
        #[arg(short, long)]
        quiet: bool,

        /// Force check even if recently checked
        #[arg(short, long)]
        force: bool,

        /// Custom storage path for rules
        #[arg(long)]
        storage: Option<PathBuf>,
    },

    /// Apply an available update
    Apply {
        /// Specific version to apply (default: latest)
        #[arg(short, long)]
        version: Option<String>,

        /// Custom storage path for rules
        #[arg(long)]
        storage: Option<PathBuf>,
    },

    /// Rollback to a previous version
    Rollback {
        /// Version to rollback to
        #[arg(short, long)]
        version: String,

        /// Custom storage path for rules
        #[arg(long)]
        storage: Option<PathBuf>,
    },

    /// Show current version and update status
    Status {
        /// Custom storage path for rules
        #[arg(long)]
        storage: Option<PathBuf>,
    },

    /// Cleanup old versions
    Cleanup {
        /// Custom storage path for rules
        #[arg(long)]
        storage: Option<PathBuf>,
    },
}

/// Logging verbosity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for tracing::Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
        }
    }
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ShellType {
    Zsh,
    Bash,
    Fish,
    All,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_default_log_level_is_warn() {
        let cli = Cli::parse_from(["pipeguard", "rules", "list"]);
        assert_eq!(cli.log_level, LogLevel::Warn);
    }

    #[test]
    fn cli_accepts_log_level_debug() {
        let cli = Cli::parse_from(["pipeguard", "--log-level", "debug", "rules", "list"]);
        assert_eq!(cli.log_level, LogLevel::Debug);
    }

    #[test]
    fn cli_accepts_log_format_json() {
        let cli = Cli::parse_from(["pipeguard", "--log-format", "json", "rules", "list"]);
        assert_eq!(cli.log_format, crate::logging::LogFormat::Json);
    }

    #[test]
    fn cli_log_level_global_works_after_subcommand() {
        // Global args can appear after the subcommand
        let cli = Cli::parse_from(["pipeguard", "rules", "list", "--log-level", "trace"]);
        assert_eq!(cli.log_level, LogLevel::Trace);
    }

    #[test]
    fn log_level_converts_to_tracing_level() {
        assert_eq!(tracing::Level::from(LogLevel::Error), tracing::Level::ERROR);
        assert_eq!(tracing::Level::from(LogLevel::Warn), tracing::Level::WARN);
        assert_eq!(tracing::Level::from(LogLevel::Info), tracing::Level::INFO);
        assert_eq!(tracing::Level::from(LogLevel::Debug), tracing::Level::DEBUG);
        assert_eq!(tracing::Level::from(LogLevel::Trace), tracing::Level::TRACE);
    }
}
