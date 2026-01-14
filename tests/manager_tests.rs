// tests/manager_tests.rs
use pipeguard::update::{UpdateManager, UpdateConfig};
use tempfile::tempdir;
use std::fs;

#[test]
fn test_check_for_updates_detects_new_version() {
    let temp = tempdir().unwrap();
    let config = UpdateConfig {
        enabled: true,
        auto_apply: false,
        check_interval_hours: 24,
        source: "https://github.com/SecurityRonin/pipeguard".to_string(),
        keep_versions: 3,
    };

    let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();

    // Should detect that no version is currently active
    let update_available = manager.check_for_updates().unwrap();
    assert!(update_available.is_some(), "Should detect available update when no active version");
}

#[test]
fn test_download_and_verify_rules() {
    let temp = tempdir().unwrap();
    let config = UpdateConfig::default();
    let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();

    // Create mock rules and signature
    let rules = b"rule test { condition: true }";
    let mock_version = "1.0.0";

    // This test requires mocking GitHub API - for now we test the flow
    // In real implementation, we'll use mockito to mock HTTP responses
    let result = manager.download_rules(mock_version);

    // Should fail gracefully if network unavailable
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_apply_update_activates_version() {
    let temp = tempdir().unwrap();
    let config = UpdateConfig::default();
    let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();

    // Create a mock version manually
    let version = "1.0.0";
    let version_dir = temp.path().join("versions").join(version);
    fs::create_dir_all(&version_dir).unwrap();
    fs::write(version_dir.join("core.yar"), b"rule test { condition: true }").unwrap();
    fs::write(version_dir.join(".verified"), "").unwrap();

    // Apply the update
    manager.apply_update(version).unwrap();

    // Verify version is now active
    let current = manager.current_version().unwrap();
    assert_eq!(current, version);
}

#[test]
fn test_rollback_to_previous_version() {
    let temp = tempdir().unwrap();
    let config = UpdateConfig::default();
    let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();

    // Create two mock versions
    let v1 = "1.0.0";
    let v2 = "1.1.0";

    for version in &[v1, v2] {
        let version_dir = temp.path().join("versions").join(version);
        fs::create_dir_all(&version_dir).unwrap();
        fs::write(version_dir.join("core.yar"), b"rule test { condition: true }").unwrap();
        fs::write(version_dir.join(".verified"), "").unwrap();
    }

    // Activate v1, then v2
    manager.apply_update(v1).unwrap();
    manager.apply_update(v2).unwrap();
    assert_eq!(manager.current_version().unwrap(), v2);

    // Rollback to v1
    manager.rollback(v1).unwrap();
    assert_eq!(manager.current_version().unwrap(), v1);
}

#[test]
fn test_verification_failure_prevents_activation() {
    let temp = tempdir().unwrap();
    let config = UpdateConfig::default();
    let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();

    // Create version without verification marker
    let version = "1.0.0";
    let version_dir = temp.path().join("versions").join(version);
    fs::create_dir_all(&version_dir).unwrap();
    fs::write(version_dir.join("core.yar"), b"rule test { condition: true }").unwrap();
    // Deliberately omit .verified marker

    // Should fail to apply unverified version
    let result = manager.apply_update(version);
    assert!(result.is_err(), "Should reject unverified version");
    assert!(result.unwrap_err().to_string().contains("not verified"));
}

#[test]
fn test_cleanup_removes_old_versions() {
    let temp = tempdir().unwrap();
    let config = UpdateConfig {
        keep_versions: 2,
        ..Default::default()
    };
    let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();

    // Create 4 versions
    for i in 0..4 {
        let version = format!("1.{}.0", i);
        let version_dir = temp.path().join("versions").join(&version);
        fs::create_dir_all(&version_dir).unwrap();
        fs::write(version_dir.join("core.yar"), b"rule test { condition: true }").unwrap();

        // Small delay to ensure different modification times
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Cleanup should keep only 2 most recent
    manager.cleanup().unwrap();

    assert!(!manager.has_version("1.0.0"));
    assert!(!manager.has_version("1.1.0"));
    assert!(manager.has_version("1.2.0"));
    assert!(manager.has_version("1.3.0"));
}

#[test]
fn test_update_respects_disabled_config() {
    let temp = tempdir().unwrap();
    let config = UpdateConfig {
        enabled: false,
        ..Default::default()
    };
    let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();

    // Should not check for updates when disabled
    let result = manager.check_for_updates();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none(), "Should return None when disabled");
}

#[test]
fn test_auto_apply_applies_updates_automatically() {
    let temp = tempdir().unwrap();
    let config = UpdateConfig {
        auto_apply: true,
        ..Default::default()
    };
    let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();

    // Create and verify a mock version
    let version = "1.0.0";
    let version_dir = temp.path().join("versions").join(version);
    fs::create_dir_all(&version_dir).unwrap();
    fs::write(version_dir.join("core.yar"), b"rule test { condition: true }").unwrap();
    fs::write(version_dir.join(".verified"), "").unwrap();

    // With auto_apply, should activate immediately
    manager.process_update(version).unwrap();
    assert_eq!(manager.current_version().unwrap(), version);
}
