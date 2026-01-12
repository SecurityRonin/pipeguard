use pipeguard::config::settings::{Config, ResponseOverride};
use pipeguard::detection::threat::{ThreatLevel, ThreatResponse};
use tempfile::TempDir;
use std::fs;

#[test]
fn config_loads_from_toml_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml_content = r#"
        [detection]
        enable_yara = true
        enable_sandbox = false
        timeout_secs = 30

        [response]
        low = "warn"
        medium = "prompt"
        high = "block"

        [rules]
        custom_rules_path = "/path/to/rules"
    "#;
    fs::write(&config_path, toml_content).unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert!(config.detection.enable_yara);
    assert!(!config.detection.enable_sandbox);
    assert_eq!(config.detection.timeout_secs, 30);
}

#[test]
fn config_uses_defaults_when_missing() {
    let config = Config::default();

    assert!(config.detection.enable_yara);
    assert!(config.detection.enable_sandbox);
    assert_eq!(config.detection.timeout_secs, 60);
    assert_eq!(config.response.low, ThreatResponse::Warn);
    assert_eq!(config.response.medium, ThreatResponse::Prompt);
    assert_eq!(config.response.high, ThreatResponse::Block);
}

#[test]
fn config_response_override_from_string() {
    assert_eq!(ResponseOverride::from_str("warn"), Some(ThreatResponse::Warn));
    assert_eq!(ResponseOverride::from_str("prompt"), Some(ThreatResponse::Prompt));
    assert_eq!(ResponseOverride::from_str("block"), Some(ThreatResponse::Block));
    assert_eq!(ResponseOverride::from_str("allow"), Some(ThreatResponse::Allow));
    assert_eq!(ResponseOverride::from_str("invalid"), None);
}

#[test]
fn config_gets_response_for_threat_level() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml_content = r#"
        [response]
        low = "allow"
        medium = "warn"
        high = "prompt"
    "#;
    fs::write(&config_path, toml_content).unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert_eq!(config.response_for(ThreatLevel::Low), ThreatResponse::Allow);
    assert_eq!(config.response_for(ThreatLevel::Medium), ThreatResponse::Warn);
    assert_eq!(config.response_for(ThreatLevel::High), ThreatResponse::Prompt);
    assert_eq!(config.response_for(ThreatLevel::None), ThreatResponse::Allow);
}

#[test]
fn config_allowlist_skips_known_safe() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let toml_content = r#"
        [allowlist]
        hashes = [
            "abc123def456",
            "789xyz000111"
        ]
        domains = [
            "brew.sh",
            "rust-lang.org"
        ]
    "#;
    fs::write(&config_path, toml_content).unwrap();

    let config = Config::from_file(&config_path).unwrap();

    assert!(config.is_allowlisted_hash("abc123def456"));
    assert!(!config.is_allowlisted_hash("unknown_hash"));
    assert!(config.is_allowlisted_domain("brew.sh"));
    assert!(!config.is_allowlisted_domain("evil.com"));
}

#[test]
fn config_finds_xdg_config_path() {
    let path = Config::default_config_path();
    assert!(path.ends_with("pipeguard/config.toml"));
}

#[test]
fn config_merges_with_defaults() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    // Partial config - only override timeout
    let toml_content = r#"
        [detection]
        timeout_secs = 120
    "#;
    fs::write(&config_path, toml_content).unwrap();

    let config = Config::from_file(&config_path).unwrap();

    // Overridden value
    assert_eq!(config.detection.timeout_secs, 120);
    // Default values preserved
    assert!(config.detection.enable_yara);
    assert!(config.detection.enable_sandbox);
}

#[test]
fn config_serializes_to_toml() {
    let config = Config::default();
    let toml_string = config.to_toml().unwrap();

    assert!(toml_string.contains("enable_yara"));
    assert!(toml_string.contains("timeout_secs"));
}
