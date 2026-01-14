// tests/config_updates_tests.rs
use pipeguard::config::settings::Config;

#[test]
fn test_default_config_includes_updates() {
    let config = Config::default();

    assert!(config.updates.enabled);
    assert!(!config.updates.auto_apply);
    assert_eq!(config.updates.check_interval_hours, 24);
    assert_eq!(config.updates.source, "https://github.com/SecurityRonin/pipeguard");
    assert_eq!(config.updates.keep_versions, 3);
}

#[test]
fn test_config_serializes_to_toml_with_updates() {
    let config = Config::default();
    let toml = config.to_toml().unwrap();

    // Verify updates section exists in TOML
    assert!(toml.contains("[updates]"));
    assert!(toml.contains("enabled = true"));
    assert!(toml.contains("auto_apply = false"));
    assert!(toml.contains("check_interval_hours = 24"));
    assert!(toml.contains("keep_versions = 3"));
}

#[test]
fn test_config_deserializes_from_toml_with_updates() {
    let toml = r#"
[detection]
enable_yara = true
enable_sandbox = true
timeout_secs = 60

[response]
low = "warn"
medium = "prompt"
high = "block"

[rules]

[allowlist]

[updates]
enabled = true
auto_apply = true
check_interval_hours = 12
source = "https://example.com/rules"
keep_versions = 5
"#;

    let config: Config = toml::from_str(toml).unwrap();

    assert!(config.updates.enabled);
    assert!(config.updates.auto_apply);
    assert_eq!(config.updates.check_interval_hours, 12);
    assert_eq!(config.updates.source, "https://example.com/rules");
    assert_eq!(config.updates.keep_versions, 5);
}
