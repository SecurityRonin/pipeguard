// Security and edge-case tests for Config module
// Covers: allowlist, response overrides, serialization, malicious input

use pipeguard::config::settings::{Config, ResponseOverride};
use pipeguard::detection::threat::{ThreatLevel, ThreatResponse};
use std::fs;
use tempfile::TempDir;

// ─── Config loading ─────────────────────────────────────────────

#[test]
fn config_from_valid_file() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[response]
low = "warn"
medium = "prompt"
high = "block"

[allowlist]
domains = []
hashes = []
"#,
    )
    .unwrap();

    let config = Config::from_file(&path).unwrap();
    assert_eq!(config.response.low, ThreatResponse::Warn);
    assert_eq!(config.response.medium, ThreatResponse::Prompt);
    assert_eq!(config.response.high, ThreatResponse::Block);
}

#[test]
fn config_from_empty_file_uses_defaults() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(&path, "").unwrap();

    let config = Config::from_file(&path).unwrap();
    assert_eq!(config.response.low, ThreatResponse::Warn);
    assert!(config.detection.enable_yara);
    assert_eq!(config.detection.timeout_secs, 60);
}

#[test]
fn config_from_nonexistent_file_errors() {
    let result = Config::from_file(std::path::Path::new("/nonexistent/config.toml"));
    assert!(result.is_err());
}

#[test]
fn config_from_invalid_toml_errors() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("bad.toml");
    fs::write(&path, "{{{{invalid toml}").unwrap();
    assert!(Config::from_file(&path).is_err());
}

#[test]
fn config_partial_sections_use_defaults() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[response]
low = "allow"
"#,
    )
    .unwrap();

    let config = Config::from_file(&path).unwrap();
    assert_eq!(config.response.low, ThreatResponse::Allow);
    // Other fields should be defaults
    assert_eq!(config.response.medium, ThreatResponse::Prompt);
    assert_eq!(config.response.high, ThreatResponse::Block);
}

// ─── Allowlist ──────────────────────────────────────────────────

#[test]
fn allowlist_hash_match() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[allowlist]
hashes = ["abc123def456"]
domains = []
"#,
    )
    .unwrap();

    let config = Config::from_file(&path).unwrap();
    assert!(config.is_allowlisted_hash("abc123def456"));
    assert!(!config.is_allowlisted_hash("different"));
}

#[test]
fn allowlist_domain_match() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[allowlist]
hashes = []
domains = ["trusted.com"]
"#,
    )
    .unwrap();

    let config = Config::from_file(&path).unwrap();
    assert!(config.is_allowlisted_domain("trusted.com"));
    assert!(!config.is_allowlisted_domain("evil.com"));
}

#[test]
fn allowlist_empty_is_default() {
    let config = Config::default();
    assert!(!config.is_allowlisted_hash("anything"));
    assert!(!config.is_allowlisted_domain("anything"));
}

#[test]
fn allowlist_multiple_entries() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[allowlist]
hashes = ["hash1", "hash2", "hash3"]
domains = ["a.com", "b.com"]
"#,
    )
    .unwrap();

    let config = Config::from_file(&path).unwrap();
    assert!(config.is_allowlisted_hash("hash1"));
    assert!(config.is_allowlisted_hash("hash2"));
    assert!(config.is_allowlisted_hash("hash3"));
    assert!(!config.is_allowlisted_hash("hash4"));
    assert!(config.is_allowlisted_domain("a.com"));
    assert!(config.is_allowlisted_domain("b.com"));
}

// ─── Response mapping ───────────────────────────────────────────

#[test]
fn response_for_none_is_allow() {
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
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[response]
low = "block"
medium = "allow"
high = "warn"
"#,
    )
    .unwrap();

    let config = Config::from_file(&path).unwrap();
    assert_eq!(config.response_for(ThreatLevel::Low), ThreatResponse::Block);
    assert_eq!(
        config.response_for(ThreatLevel::Medium),
        ThreatResponse::Allow
    );
    assert_eq!(config.response_for(ThreatLevel::High), ThreatResponse::Warn);
}

// ─── ResponseOverride ───────────────────────────────────────────

#[test]
fn response_override_valid_values() {
    assert_eq!(
        ResponseOverride::parse("allow"),
        Some(ThreatResponse::Allow)
    );
    assert_eq!(ResponseOverride::parse("warn"), Some(ThreatResponse::Warn));
    assert_eq!(
        ResponseOverride::parse("prompt"),
        Some(ThreatResponse::Prompt)
    );
    assert_eq!(
        ResponseOverride::parse("block"),
        Some(ThreatResponse::Block)
    );
}

#[test]
fn response_override_case_insensitive() {
    assert_eq!(
        ResponseOverride::parse("ALLOW"),
        Some(ThreatResponse::Allow)
    );
    assert_eq!(
        ResponseOverride::parse("Block"),
        Some(ThreatResponse::Block)
    );
    assert_eq!(ResponseOverride::parse("WARN"), Some(ThreatResponse::Warn));
}

#[test]
fn response_override_invalid_returns_none() {
    assert_eq!(ResponseOverride::parse("invalid"), None);
    assert_eq!(ResponseOverride::parse(""), None);
    assert_eq!(ResponseOverride::parse("kill"), None);
}

// ─── Serialization roundtrip ────────────────────────────────────

#[test]
fn config_to_toml_roundtrip() {
    let config = Config::default();
    let toml_str = config.to_toml().unwrap();

    let temp = TempDir::new().unwrap();
    let path = temp.path().join("roundtrip.toml");
    fs::write(&path, &toml_str).unwrap();

    let loaded = Config::from_file(&path).unwrap();
    assert_eq!(loaded.response.low, config.response.low);
    assert_eq!(loaded.response.medium, config.response.medium);
    assert_eq!(loaded.response.high, config.response.high);
    assert_eq!(loaded.detection.enable_yara, config.detection.enable_yara);
    assert_eq!(loaded.updates.enabled, config.updates.enabled);
}

// ─── Updates config ─────────────────────────────────────────────

#[test]
fn updates_config_defaults() {
    let config = Config::default();
    assert!(config.updates.enabled);
    assert!(!config.updates.auto_apply);
    assert_eq!(config.updates.check_interval_hours, 24);
    assert_eq!(config.updates.keep_versions, 3);
}

#[test]
fn updates_config_from_file() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[updates]
enabled = false
auto_apply = true
check_interval_hours = 12
keep_versions = 5
"#,
    )
    .unwrap();

    let config = Config::from_file(&path).unwrap();
    assert!(!config.updates.enabled);
    assert!(config.updates.auto_apply);
    assert_eq!(config.updates.check_interval_hours, 12);
    assert_eq!(config.updates.keep_versions, 5);
}

// ─── Invalid response values ────────────────────────────────────

#[test]
fn config_invalid_response_value_errors() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[response]
low = "explode"
"#,
    )
    .unwrap();

    assert!(Config::from_file(&path).is_err());
}

// ─── Detection config ───────────────────────────────────────────

#[test]
fn detection_config_defaults() {
    let config = Config::default();
    assert!(config.detection.enable_yara);
    assert_eq!(config.detection.timeout_secs, 60);
}

#[test]
fn detection_config_custom() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.toml");
    fs::write(
        &path,
        r#"
[detection]
enable_yara = false
timeout_secs = 30
"#,
    )
    .unwrap();

    let config = Config::from_file(&path).unwrap();
    assert!(!config.detection.enable_yara);
    assert_eq!(config.detection.timeout_secs, 30);
}

// ─── Default config path ────────────────────────────────────────

#[test]
fn default_config_path_is_reasonable() {
    let path = Config::default_config_path();
    let path_str = path.to_string_lossy();
    assert!(
        path_str.contains("pipeguard") && path_str.contains("config.toml"),
        "Expected pipeguard/config.toml path, got: {}",
        path_str
    );
}
