//! Exhaustive tests for configuration system.

use pipeguard::config::settings::{Config, ResponseOverride};
use pipeguard::detection::threat::{ThreatLevel, ThreatResponse};
use std::fs;
use tempfile::TempDir;

// =============================================================================
// Config loading tests
// =============================================================================

#[test]
fn load_full_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [detection]
        enable_yara = true
        enable_sandbox = true
        timeout_secs = 45

        [response]
        low = "warn"
        medium = "prompt"
        high = "block"

        [rules]
        custom_rules_path = "/custom/rules"

        [allowlist]
        hashes = ["abc123", "def456"]
        domains = ["example.com", "trusted.org"]
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(config.detection.enable_yara);
    assert!(config.detection.enable_sandbox);
    assert_eq!(config.detection.timeout_secs, 45);
}

#[test]
fn load_minimal_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [detection]
        timeout_secs = 30
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert_eq!(config.detection.timeout_secs, 30);
    // Defaults should be used
    assert!(config.detection.enable_yara);
}

#[test]
fn load_empty_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    fs::write(&config_path, "").unwrap();

    let config = Config::from_file(&config_path).unwrap();
    // All defaults
    assert!(config.detection.enable_yara);
    assert!(config.detection.enable_sandbox);
    assert_eq!(config.detection.timeout_secs, 60);
}

#[test]
fn load_nonexistent_file_fails() {
    let result = Config::from_file(std::path::Path::new("/nonexistent/config.toml"));
    assert!(result.is_err());
}

#[test]
fn load_invalid_toml_fails() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    fs::write(&config_path, "this is not valid toml {{{").unwrap();

    let result = Config::from_file(&config_path);
    assert!(result.is_err());
}

// =============================================================================
// Default values tests
// =============================================================================

#[test]
fn default_detection_enable_yara() {
    let config = Config::default();
    assert!(config.detection.enable_yara);
}

#[test]
fn default_detection_enable_sandbox() {
    let config = Config::default();
    assert!(config.detection.enable_sandbox);
}

#[test]
fn default_detection_timeout() {
    let config = Config::default();
    assert_eq!(config.detection.timeout_secs, 60);
}

#[test]
fn default_response_low() {
    let config = Config::default();
    assert_eq!(config.response.low, ThreatResponse::Warn);
}

#[test]
fn default_response_medium() {
    let config = Config::default();
    assert_eq!(config.response.medium, ThreatResponse::Prompt);
}

#[test]
fn default_response_high() {
    let config = Config::default();
    assert_eq!(config.response.high, ThreatResponse::Block);
}

#[test]
fn default_rules_path_none() {
    let config = Config::default();
    assert!(config.rules.custom_rules_path.is_none());
}

// =============================================================================
// ResponseOverride tests
// =============================================================================

#[test]
fn response_override_allow() {
    assert_eq!(
        ResponseOverride::parse("allow"),
        Some(ThreatResponse::Allow)
    );
}

#[test]
fn response_override_warn() {
    assert_eq!(ResponseOverride::parse("warn"), Some(ThreatResponse::Warn));
}

#[test]
fn response_override_prompt() {
    assert_eq!(
        ResponseOverride::parse("prompt"),
        Some(ThreatResponse::Prompt)
    );
}

#[test]
fn response_override_block() {
    assert_eq!(
        ResponseOverride::parse("block"),
        Some(ThreatResponse::Block)
    );
}

#[test]
fn response_override_case_insensitive_upper() {
    assert_eq!(
        ResponseOverride::parse("ALLOW"),
        Some(ThreatResponse::Allow)
    );
    assert_eq!(ResponseOverride::parse("WARN"), Some(ThreatResponse::Warn));
    assert_eq!(
        ResponseOverride::parse("PROMPT"),
        Some(ThreatResponse::Prompt)
    );
    assert_eq!(
        ResponseOverride::parse("BLOCK"),
        Some(ThreatResponse::Block)
    );
}

#[test]
fn response_override_case_insensitive_mixed() {
    assert_eq!(
        ResponseOverride::parse("AlLoW"),
        Some(ThreatResponse::Allow)
    );
    assert_eq!(ResponseOverride::parse("WaRn"), Some(ThreatResponse::Warn));
}

#[test]
fn response_override_invalid() {
    assert_eq!(ResponseOverride::parse("invalid"), None);
    assert_eq!(ResponseOverride::parse(""), None);
    assert_eq!(ResponseOverride::parse("  "), None);
    assert_eq!(ResponseOverride::parse("blockkk"), None);
}

// =============================================================================
// response_for tests
// =============================================================================

#[test]
fn response_for_none() {
    let config = Config::default();
    assert_eq!(
        config.response_for(ThreatLevel::None),
        ThreatResponse::Allow
    );
}

#[test]
fn response_for_low_default() {
    let config = Config::default();
    assert_eq!(config.response_for(ThreatLevel::Low), ThreatResponse::Warn);
}

#[test]
fn response_for_medium_default() {
    let config = Config::default();
    assert_eq!(
        config.response_for(ThreatLevel::Medium),
        ThreatResponse::Prompt
    );
}

#[test]
fn response_for_high_default() {
    let config = Config::default();
    assert_eq!(
        config.response_for(ThreatLevel::High),
        ThreatResponse::Block
    );
}

#[test]
fn response_for_custom_overrides() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [response]
        low = "allow"
        medium = "warn"
        high = "prompt"
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert_eq!(config.response_for(ThreatLevel::Low), ThreatResponse::Allow);
    assert_eq!(
        config.response_for(ThreatLevel::Medium),
        ThreatResponse::Warn
    );
    assert_eq!(
        config.response_for(ThreatLevel::High),
        ThreatResponse::Prompt
    );
}

// =============================================================================
// Allowlist tests
// =============================================================================

#[test]
fn allowlist_hash_found() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [allowlist]
        hashes = ["abc123", "def456", "ghi789"]
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(config.is_allowlisted_hash("abc123"));
    assert!(config.is_allowlisted_hash("def456"));
    assert!(config.is_allowlisted_hash("ghi789"));
}

#[test]
fn allowlist_hash_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [allowlist]
        hashes = ["abc123"]
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(!config.is_allowlisted_hash("unknown"));
    assert!(!config.is_allowlisted_hash(""));
}

#[test]
fn allowlist_hash_empty_list() {
    let config = Config::default();
    assert!(!config.is_allowlisted_hash("anything"));
}

#[test]
fn allowlist_domain_found() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [allowlist]
        domains = ["brew.sh", "rust-lang.org", "github.com"]
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(config.is_allowlisted_domain("brew.sh"));
    assert!(config.is_allowlisted_domain("rust-lang.org"));
    assert!(config.is_allowlisted_domain("github.com"));
}

#[test]
fn allowlist_domain_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [allowlist]
        domains = ["trusted.com"]
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(!config.is_allowlisted_domain("evil.com"));
    assert!(!config.is_allowlisted_domain(""));
}

#[test]
fn allowlist_domain_empty_list() {
    let config = Config::default();
    assert!(!config.is_allowlisted_domain("anything.com"));
}

// =============================================================================
// Config path tests
// =============================================================================

#[test]
fn default_config_path_contains_pipeguard() {
    let path = Config::default_config_path();
    assert!(path.to_string_lossy().contains("pipeguard"));
}

#[test]
fn default_config_path_ends_with_toml() {
    let path = Config::default_config_path();
    assert!(path.to_string_lossy().ends_with(".toml"));
}

// =============================================================================
// Serialization tests
// =============================================================================

#[test]
fn to_toml_contains_detection() {
    let config = Config::default();
    let toml = config.to_toml().unwrap();
    assert!(toml.contains("[detection]"));
}

#[test]
fn to_toml_contains_response() {
    let config = Config::default();
    let toml = config.to_toml().unwrap();
    assert!(toml.contains("[response]"));
}

#[test]
fn to_toml_contains_enable_yara() {
    let config = Config::default();
    let toml = config.to_toml().unwrap();
    assert!(toml.contains("enable_yara"));
}

#[test]
fn to_toml_contains_timeout() {
    let config = Config::default();
    let toml = config.to_toml().unwrap();
    assert!(toml.contains("timeout_secs"));
}

#[test]
fn to_toml_roundtrip() {
    let original = Config::default();
    let toml = original.to_toml().unwrap();

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    fs::write(&config_path, &toml).unwrap();

    let loaded = Config::from_file(&config_path).unwrap();

    assert_eq!(original.detection.enable_yara, loaded.detection.enable_yara);
    assert_eq!(
        original.detection.timeout_secs,
        loaded.detection.timeout_secs
    );
    assert_eq!(original.response.low, loaded.response.low);
    assert_eq!(original.response.high, loaded.response.high);
}

// =============================================================================
// Edge cases
// =============================================================================

#[test]
fn config_with_extra_fields_ignored() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [detection]
        enable_yara = true
        some_future_field = "ignored"
        another_field = 42

        [unknown_section]
        foo = "bar"
    "#;
    fs::write(&config_path, toml).unwrap();

    // Should not fail, just ignore unknown fields
    let config = Config::from_file(&config_path).unwrap();
    assert!(config.detection.enable_yara);
}

#[test]
fn config_with_unicode_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [allowlist]
        domains = ["例え.jp", "пример.рф"]
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(config.is_allowlisted_domain("例え.jp"));
    assert!(config.is_allowlisted_domain("пример.рф"));
}

#[test]
fn config_timeout_zero() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [detection]
        timeout_secs = 0
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert_eq!(config.detection.timeout_secs, 0);
}

#[test]
fn config_timeout_large() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [detection]
        timeout_secs = 3600
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert_eq!(config.detection.timeout_secs, 3600);
}

#[test]
fn config_detection_disabled() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [detection]
        enable_yara = false
        enable_sandbox = false
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert!(!config.detection.enable_yara);
    assert!(!config.detection.enable_sandbox);
}

#[test]
fn config_all_responses_allow() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [response]
        low = "allow"
        medium = "allow"
        high = "allow"
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert_eq!(config.response.low, ThreatResponse::Allow);
    assert_eq!(config.response.medium, ThreatResponse::Allow);
    assert_eq!(config.response.high, ThreatResponse::Allow);
}

#[test]
fn config_all_responses_block() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml = r#"
        [response]
        low = "block"
        medium = "block"
        high = "block"
    "#;
    fs::write(&config_path, toml).unwrap();

    let config = Config::from_file(&config_path).unwrap();
    assert_eq!(config.response.low, ThreatResponse::Block);
    assert_eq!(config.response.medium, ThreatResponse::Block);
    assert_eq!(config.response.high, ThreatResponse::Block);
}
