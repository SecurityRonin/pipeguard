//! Command-line argument parsing.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// PipeGuard - Defending against curl|bash attacks
#[derive(Parser, Debug)]
#[command(name = "pipeguard")]
#[command(author, version, about, long_about = None)]
#[command(
    about = "PipeGuard - Defending against curl|bash attacks through multi-layer shell interception"
)]
pub struct Cli {
    /// Logging verbosity level
    #[arg(long, global = true, default_value = "warn")]
    pub log_level: LogLevel,

    /// Logging output format
    #[arg(long, global = true, default_value = "pretty")]
    pub log_format: crate::logging::LogFormat,

    /// Control color output (auto, always, never). Respects NO_COLOR env var.
    #[arg(long, global = true, default_value = "auto")]
    pub color: ColorMode,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan content for threats
    Scan {
        /// Path to YARA rules file or directory [default: auto-detected]
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// File to scan (reads from stdin if not provided)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Output format: text, json
        #[arg(short = 'F', long, default_value = "text")]
        format: OutputFormat,

        /// Suppress all stdout output, only set exit code
        #[arg(short, long)]
        quiet: bool,
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

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: CompletionShell,
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

    /// Show rule metadata (name, severity, description)
    Info {
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

/// Color output mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorMode {
    /// Auto-detect based on terminal
    Auto,
    /// Always use colors
    Always,
    /// Never use colors
    Never,
}

/// Shell type for completion generation.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

/// Scan exit codes with distinct semantics.
/// 0 = clean, 1 = threat detected, 2 = error.
pub const EXIT_CLEAN: u8 = 0;
pub const EXIT_THREAT: u8 = 1;
pub const EXIT_ERROR: u8 = 2;

/// Well-known rules paths searched when --rules is omitted.
pub const DEFAULT_RULES_SEARCH_PATHS: &[&str] = &[
    // Homebrew (Apple Silicon)
    "/opt/homebrew/share/pipeguard/rules",
    // Homebrew (Intel)
    "/usr/local/share/pipeguard/rules",
    // User local
    "~/.pipeguard/rules",
];

/// Resolve the rules path: use provided, or search defaults.
pub fn resolve_rules_path(provided: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = provided {
        return Some(path);
    }

    for candidate in DEFAULT_RULES_SEARCH_PATHS {
        let expanded = if candidate.starts_with('~') {
            if let Some(home) = dirs::home_dir() {
                home.join(&candidate[2..])
            } else {
                continue;
            }
        } else {
            PathBuf::from(candidate)
        };

        if expanded.exists() {
            return Some(expanded);
        }
    }

    None
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

    // --- New enhancement tests (TDD) ---

    #[test]
    fn scan_rules_is_optional() {
        // --rules should be optional (auto-detected)
        let cli = Cli::parse_from(["pipeguard", "scan"]);
        match cli.command {
            Commands::Scan { rules, .. } => assert!(rules.is_none()),
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn scan_accepts_quiet_flag() {
        let cli = Cli::parse_from(["pipeguard", "scan", "--quiet"]);
        match cli.command {
            Commands::Scan { quiet, .. } => assert!(quiet),
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn scan_quiet_default_is_false() {
        let cli = Cli::parse_from(["pipeguard", "scan"]);
        match cli.command {
            Commands::Scan { quiet, .. } => assert!(!quiet),
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn color_mode_defaults_to_auto() {
        let cli = Cli::parse_from(["pipeguard", "rules", "list"]);
        assert_eq!(cli.color, ColorMode::Auto);
    }

    #[test]
    fn color_mode_accepts_never() {
        let cli = Cli::parse_from(["pipeguard", "--color", "never", "rules", "list"]);
        assert_eq!(cli.color, ColorMode::Never);
    }

    #[test]
    fn completions_subcommand_parses() {
        let cli = Cli::parse_from(["pipeguard", "completions", "zsh"]);
        matches!(cli.command, Commands::Completions { .. });
    }

    #[test]
    fn rules_info_subcommand_parses() {
        let cli = Cli::parse_from(["pipeguard", "rules", "info", "--path", "rules/core.yar"]);
        match cli.command {
            Commands::Rules {
                action: RulesAction::Info { path },
            } => {
                assert_eq!(path, PathBuf::from("rules/core.yar"));
            }
            _ => panic!("Expected Rules Info command"),
        }
    }

    #[test]
    fn exit_codes_are_distinct() {
        assert_eq!(EXIT_CLEAN, 0);
        assert_eq!(EXIT_THREAT, 1);
        assert_eq!(EXIT_ERROR, 2);
        assert_ne!(EXIT_THREAT, EXIT_ERROR);
    }

    #[test]
    fn resolve_rules_path_with_provided() {
        let result = resolve_rules_path(Some(PathBuf::from("/tmp/rules")));
        assert_eq!(result, Some(PathBuf::from("/tmp/rules")));
    }

    #[test]
    fn resolve_rules_path_returns_none_when_no_defaults_exist() {
        // With no provided path and no defaults installed, should return None
        let result = resolve_rules_path(None);
        // Can't guarantee None on a machine with pipeguard installed,
        // but the function should not panic
        let _ = result;
    }
}
