//! Install command: set up shell integration hooks for bash, zsh, and fish.

use anyhow::Context;
use colored::*;
use std::path::Path;
use std::process::ExitCode;
use tracing::{debug, info};

use crate::cli::args::ShellType;

/// Execute the `install` command: add PipeGuard shell hooks to RC files.
pub fn cmd_install(dry_run: bool, shell: ShellType) -> anyhow::Result<ExitCode> {
    let shells_to_install = match shell {
        ShellType::Zsh => vec!["zsh"],
        ShellType::Bash => vec!["bash"],
        ShellType::Fish => vec!["fish"],
        ShellType::All => vec!["zsh", "bash"], // Fish support TBD
    };

    // Get executable directory (for finding shell hooks)
    let exe_dir = std::env::current_exe()
        .context("Failed to determine current executable path")?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Could not determine executable directory"))?
        .to_path_buf();

    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    for s in &shells_to_install {
        match *s {
            "bash" => {
                let rc_file = home.join(".bashrc");
                let hook_path = exe_dir.join("../shell/pipeguard.bash");

                install_shell_hook(&rc_file, &hook_path, "bash", dry_run)?;
            }
            "zsh" => {
                let rc_file = home.join(".zshrc");
                let hook_path = exe_dir.join("../shell/pipeguard.zsh");

                install_shell_hook(&rc_file, &hook_path, "zsh", dry_run)?;
            }
            "fish" => {
                println!("  {} Fish integration not yet implemented", "⚠️".yellow());
            }
            _ => {}
        }
    }

    if !dry_run {
        println!();
        println!("{} Shell integration installed!", "✓".green());
        println!("Restart your shell or run:");
        if shells_to_install.contains(&"bash") {
            println!("  source ~/.bashrc");
        }
        if shells_to_install.contains(&"zsh") {
            println!("  source ~/.zshrc");
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn install_shell_hook(
    rc_file: &Path,
    hook_path: &Path,
    shell_name: &str,
    dry_run: bool,
) -> anyhow::Result<()> {
    let source_line = format!(
        "\n# PipeGuard integration\n[ -f \"{}\" ] && source \"{}\"\n",
        hook_path.display(),
        hook_path.display()
    );

    if dry_run {
        println!("Would add to {}:", rc_file.display());
        println!("{}", source_line.trim());
        return Ok(());
    }

    // Check if already installed
    if rc_file.exists() {
        let content = std::fs::read_to_string(rc_file)
            .with_context(|| format!("Failed to read shell config '{}'", rc_file.display()))?;
        if content.contains("PipeGuard integration") {
            println!(
                "  {} {} integration already installed",
                "✓".green(),
                shell_name
            );
            debug!(shell = shell_name, "Shell integration already installed");
            return Ok(());
        }
    }

    // Create RC file if it doesn't exist
    if !rc_file.exists() {
        std::fs::File::create(rc_file)
            .with_context(|| format!("Failed to create shell config '{}'", rc_file.display()))?;
    }

    // Append source line
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(rc_file)
        .with_context(|| {
            format!(
                "Failed to open shell config '{}' for writing",
                rc_file.display()
            )
        })?;
    file.write_all(source_line.as_bytes())
        .with_context(|| format!("Failed to write to shell config '{}'", rc_file.display()))?;

    println!("  {} Installed {} integration", "✓".green(), shell_name);
    info!(shell = shell_name, "Shell integration installed");
    Ok(())
}
