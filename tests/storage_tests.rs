// tests/storage_tests.rs
use pipeguard::update::VersionedStorage;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_create_version_directory() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    let version_path = storage.create_version_dir("1.0.0").unwrap();

    assert!(version_path.exists());
    assert!(version_path
        .join("..")
        .join("..")
        .join("versions")
        .join("1.0.0")
        .exists());
}

#[test]
fn test_write_and_read_rules() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    let version_path = storage.create_version_dir("1.0.0").unwrap();
    let rules = b"rule test { condition: true }";

    storage.write_rules(&version_path, rules).unwrap();

    let read_rules = storage.read_rules(&version_path).unwrap();
    assert_eq!(rules.to_vec(), read_rules);
}

#[test]
fn test_activate_version_creates_symlink() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    storage.create_version_dir("1.0.0").unwrap();
    storage.mark_verified("1.0.0").unwrap();
    storage.activate_version("1.0.0").unwrap();

    let active_link = temp.path().join("active");
    assert!(active_link.exists());
    assert!(active_link.read_link().is_ok());
}

#[test]
fn test_current_version_returns_active() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    storage.create_version_dir("1.0.0").unwrap();
    storage.mark_verified("1.0.0").unwrap();
    storage.activate_version("1.0.0").unwrap();

    let current = storage.current_version().unwrap();
    assert_eq!(current, Some("1.0.0".to_string()));
}

#[test]
fn test_cleanup_keeps_latest_versions() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    // Create 5 versions
    for i in 0..5 {
        storage.create_version_dir(&format!("1.{}.0", i)).unwrap();
    }

    // Cleanup, keep only 3
    storage.cleanup_old_versions(3).unwrap();

    assert!(storage.has_version("1.4.0"));
    assert!(storage.has_version("1.3.0"));
    assert!(storage.has_version("1.2.0"));
    assert!(!storage.has_version("1.1.0"));
    assert!(!storage.has_version("1.0.0"));
}

#[test]
fn test_is_verified_checks_marker() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    let version_path = storage.create_version_dir("1.0.0").unwrap();

    assert!(!storage.is_verified("1.0.0").unwrap());

    fs::write(version_path.join(".verified"), "").unwrap();

    assert!(storage.is_verified("1.0.0").unwrap());
}

#[test]
fn test_rollback_switches_active_symlink() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    storage.create_version_dir("1.0.0").unwrap();
    storage.mark_verified("1.0.0").unwrap();
    storage.create_version_dir("1.1.0").unwrap();
    storage.mark_verified("1.1.0").unwrap();

    storage.activate_version("1.1.0").unwrap();
    assert_eq!(
        storage.current_version().unwrap(),
        Some("1.1.0".to_string())
    );

    storage.activate_version("1.0.0").unwrap();
    assert_eq!(
        storage.current_version().unwrap(),
        Some("1.0.0".to_string())
    );
}

#[test]
fn test_activation_is_atomic() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    storage.create_version_dir("1.0.0").unwrap();
    storage.mark_verified("1.0.0").unwrap();
    storage.create_version_dir("1.1.0").unwrap();
    storage.mark_verified("1.1.0").unwrap();
    storage.activate_version("1.0.0").unwrap();

    // Activation should never leave broken symlink
    storage.activate_version("1.1.0").unwrap();

    let active_link = temp.path().join("active");
    assert!(active_link.exists());
    assert!(active_link.read_link().is_ok());
    assert_eq!(
        storage.current_version().unwrap(),
        Some("1.1.0".to_string())
    );
}
