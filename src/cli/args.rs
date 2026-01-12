//! Command-line argument parsing.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// PipeGuard - Defending against curl|bash attacks
#[derive(Parser, Debug)]
#[command(name = "pipeguard")]
#[command(author, version, about, long_about = None)]
#[command(about = "PipeGuard - Defending against curl|bash attacks through multi-layer shell interception")]
pub struct Cli {
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
