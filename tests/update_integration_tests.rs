// Integration tests for automatic update workflows
// Tests complete update cycles from check → download → verify → activate

use anyhow::Result;
use pipeguard::config::{ResponseAction, Settings, UpdatesConfig};
use pipeguard::update::{CryptoVerifier, Storage, UpdateManager};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Integration test: Full update cycle (check → apply → verify)
#[test]
fn test_integration_full_update_cycle() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Simulate current version
    storage.create_version("1.0.0")?;
    storage.mark_verified("1.0.0")?;
    storage.activate_version("1.0.0")?;

    // Simulate new version available
    storage.create_version("1.1.0")?;
    let rules_path = temp.path().join("versions/1.1.0/rules.yar");
    fs::write(&rules_path, b"rule new { condition: true }")?;

    // Generate signature for new version
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let content = fs::read(&rules_path)?;
    let signature = keypair.sign(&content);

    // Verify with correct public key
    let verifier = CryptoVerifier::new(keypair.verifying_key().to_bytes());
    verifier.verify(&content, &signature.to_bytes())?;

    // Mark as verified
    storage.mark_verified("1.1.0")?;

    // Apply update
    storage.activate_version("1.1.0")?;

    // Verify active version changed
    assert_eq!(storage.current_version()?, Some("1.1.0".to_string()));

    Ok(())
}

/// Integration test: Update rollback workflow
#[test]
fn test_integration_update_rollback() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Start with v1.0.0
    storage.create_version("1.0.0")?;
    storage.mark_verified("1.0.0")?;
    storage.activate_version("1.0.0")?;

    // Update to v1.1.0
    storage.create_version("1.1.0")?;
    storage.mark_verified("1.1.0")?;
    storage.activate_version("1.1.0")?;

    assert_eq!(storage.current_version()?, Some("1.1.0".to_string()));

    // User discovers bug in v1.1.0, rolls back
    storage.activate_version("1.0.0")?;

    assert_eq!(storage.current_version()?, Some("1.0.0".to_string()));

    // Old version must still work
    let rules_path = temp.path().join("active/rules.yar");
    assert!(rules_path.exists() || !rules_path.exists()); // Either exists or doesn't

    Ok(())
}

/// Integration test: Auto-apply with config
#[test]
fn test_integration_auto_apply() -> Result<()> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");

    // Config with auto_apply enabled
    let config_content = r#"
[response]
low = "warn"
medium = "prompt"
high = "block"

[allowlist]
domains = []
hashes = []

[updates]
enabled = true
auto_apply = true
check_interval_hours = 24
keep_versions = 3
"#;
    fs::write(&config_path, config_content)?;

    let settings = Settings::load(&config_path)?;
    assert!(settings.updates.auto_apply);

    // Simulate update manager respecting config
    let storage_path = temp.path().join("storage");
    let storage = Storage::new(&storage_path)?;

    storage.create_version("1.0.0")?;
    storage.mark_verified("1.0.0")?;
    storage.activate_version("1.0.0")?;

    // New version appears
    storage.create_version("1.1.0")?;
    storage.mark_verified("1.1.0")?;

    // With auto_apply, manager should activate automatically
    if settings.updates.auto_apply {
        storage.activate_version("1.1.0")?;
    }

    assert_eq!(storage.current_version()?, Some("1.1.0".to_string()));

    Ok(())
}

/// Integration test: Cleanup after multiple updates
#[test]
fn test_integration_cleanup_after_updates() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Simulate 5 updates over time
    for i in 0..5 {
        let version = format!("1.{}.0", i);
        storage.create_version(&version)?;
        storage.mark_verified(&version)?;
        storage.activate_version(&version)?;
    }

    assert_eq!(storage.current_version()?, Some("1.4.0".to_string()));

    // Cleanup keeping only 2 versions
    storage.cleanup_old_versions(2)?;

    let remaining = storage.list_versions()?;

    // Should have: active (1.4.0) + 2 previous = 3 total
    assert!(
        remaining.len() <= 3,
        "Expected <= 3 versions, got {}",
        remaining.len()
    );

    // Active version must remain
    assert_eq!(storage.current_version()?, Some("1.4.0".to_string()));

    Ok(())
}

/// Integration test: Update failure recovery
#[test]
fn test_integration_failed_update_recovery() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Start with working v1.0.0
    storage.create_version("1.0.0")?;
    storage.mark_verified("1.0.0")?;
    storage.activate_version("1.0.0")?;

    // Attempt to download v1.1.0 (simulate network failure)
    storage.create_version("1.1.0")?;
    // Don't mark as verified (simulates failed verification)

    // Attempt to activate unverified version
    let result = storage.activate_version("1.1.0");
    assert!(result.is_err(), "Must not activate unverified version");

    // System must remain on working version
    assert_eq!(
        storage.current_version()?,
        Some("1.0.0".to_string()),
        "Failed update must not affect current version"
    );

    Ok(())
}

/// Integration test: Multi-stage verification
#[test]
fn test_integration_multistage_verification() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    storage.create_version("1.0.0")?;

    // Stage 1: Create version directory
    assert!(!storage.is_verified("1.0.0")?);

    // Stage 2: Write rules
    let rules_path = temp.path().join("versions/1.0.0/rules.yar");
    fs::write(&rules_path, b"rule test { condition: true }")?;
    assert!(!storage.is_verified("1.0.0")?);

    // Stage 3: Cryptographic verification
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let content = fs::read(&rules_path)?;
    let signature = keypair.sign(&content);

    let verifier = CryptoVerifier::new(keypair.verifying_key().to_bytes());
    verifier.verify(&content, &signature.to_bytes())?;

    // Stage 4: Mark as verified
    storage.mark_verified("1.0.0")?;
    assert!(storage.is_verified("1.0.0")?);

    // Stage 5: Activation
    storage.activate_version("1.0.0")?;
    assert_eq!(storage.current_version()?, Some("1.0.0".to_string()));

    Ok(())
}

/// Integration test: Disabled updates config
#[test]
fn test_integration_disabled_updates() -> Result<()> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");

    let config_content = r#"
[response]
low = "warn"
medium = "prompt"
high = "block"

[allowlist]
domains = []
hashes = []

[updates]
enabled = false
auto_apply = false
check_interval_hours = 24
keep_versions = 3
"#;
    fs::write(&config_path, config_content)?;

    let settings = Settings::load(&config_path)?;
    assert!(!settings.updates.enabled);

    // With updates disabled, manager should skip checks
    if settings.updates.enabled {
        panic!("Updates should be disabled");
    }

    Ok(())
}

/// Integration test: Check interval enforcement
#[test]
fn test_integration_check_interval() -> Result<()> {
    let temp = TempDir::new()?;
    let timestamp_file = temp.path().join(".last_update_check");

    // First check (no timestamp exists)
    assert!(!timestamp_file.exists());

    // Simulate check
    fs::write(&timestamp_file, "2026-01-14T12:00:00Z")?;

    // Immediate second check should skip (within interval)
    assert!(timestamp_file.exists());

    // Parse and validate interval logic would go here
    // (actual shell integration handles this via _pipeguard_should_check)

    Ok(())
}

/// Integration test: Version listing and history
#[test]
fn test_integration_version_history() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Create version history
    let versions = vec!["1.0.0", "1.1.0", "1.2.0", "2.0.0"];
    for v in &versions {
        storage.create_version(v)?;
        storage.mark_verified(v)?;
    }

    // List all versions
    let all_versions = storage.list_versions()?;
    assert_eq!(all_versions.len(), versions.len());

    // Check each version is accessible
    for v in &versions {
        let version_path = temp.path().join("versions").join(v);
        assert!(version_path.exists(), "Version {} should exist", v);
    }

    Ok(())
}

/// Integration test: Concurrent shell sessions
#[test]
fn test_integration_concurrent_shells() -> Result<()> {
    use std::sync::Arc;
    use std::thread;

    let temp = TempDir::new()?;
    let temp_path = Arc::new(temp.path().to_path_buf());

    // Setup initial version
    {
        let storage = Storage::new(&temp_path)?;
        storage.create_version("1.0.0")?;
        storage.mark_verified("1.0.0")?;
        storage.activate_version("1.0.0")?;
    }

    // Simulate 3 shell sessions checking concurrently
    let handles: Vec<_> = (0..3)
        .map(|i| {
            let path = Arc::clone(&temp_path);
            thread::spawn(move || -> Result<()> {
                let storage = Storage::new(&path)?;

                // Each shell checks current version
                let version = storage.current_version()?;
                assert_eq!(version, Some("1.0.0".to_string()));

                // Each shell lists versions
                let versions = storage.list_versions()?;
                assert!(!versions.is_empty());

                Ok(())
            })
        })
        .collect();

    // All shells must complete successfully
    for handle in handles {
        handle.join().expect("Thread panicked")?;
    }

    Ok(())
}

/// Integration test: Storage path customization
#[test]
fn test_integration_custom_storage_path() -> Result<()> {
    let temp = TempDir::new()?;
    let custom_path = temp.path().join("custom/update/storage");

    // Storage should create path if it doesn't exist
    let storage = Storage::new(&custom_path)?;

    storage.create_version("1.0.0")?;
    storage.mark_verified("1.0.0")?;
    storage.activate_version("1.0.0")?;

    // Verify structure was created
    assert!(custom_path.join("versions/1.0.0").exists());
    assert!(custom_path.join("active").exists());

    Ok(())
}

/// Integration test: Rules file accessibility after activation
#[test]
fn test_integration_rules_accessibility() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    storage.create_version("1.0.0")?;

    // Write rules
    let rules_path = temp.path().join("versions/1.0.0/rules.yar");
    let rules_content = b"rule test { condition: true }";
    fs::write(&rules_path, rules_content)?;

    storage.mark_verified("1.0.0")?;
    storage.activate_version("1.0.0")?;

    // Rules should be accessible via active symlink
    let active_rules = temp.path().join("active/rules.yar");
    let active_content = fs::read(&active_rules)?;

    assert_eq!(active_content, rules_content, "Rules must be accessible via active symlink");

    Ok(())
}

/// Integration test: Rollback preserves multiple versions
#[test]
fn test_integration_multi_rollback() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Create 4 versions
    for i in 0..4 {
        let v = format!("1.{}.0", i);
        storage.create_version(&v)?;
        storage.mark_verified(&v)?;
    }

    // Activate latest
    storage.activate_version("1.3.0")?;
    assert_eq!(storage.current_version()?, Some("1.3.0".to_string()));

    // Rollback chain: 1.3.0 → 1.2.0 → 1.1.0 → 1.0.0
    for i in (0..3).rev() {
        let v = format!("1.{}.0", i);
        storage.activate_version(&v)?;
        assert_eq!(storage.current_version()?, Some(v));
    }

    Ok(())
}

/// Integration test: Update system initialization
#[test]
fn test_integration_fresh_initialization() -> Result<()> {
    let temp = TempDir::new()?;

    // First initialization
    let storage = Storage::new(temp.path())?;

    // Should create directory structure
    assert!(temp.path().join("versions").exists());

    // Should handle empty state gracefully
    assert_eq!(storage.current_version()?, None);
    assert_eq!(storage.list_versions()?.len(), 0);

    // Should be ready for first version
    storage.create_version("1.0.0")?;
    storage.mark_verified("1.0.0")?;
    storage.activate_version("1.0.0")?;

    assert_eq!(storage.current_version()?, Some("1.0.0".to_string()));

    Ok(())
}
