// tests/cli_update_tests.rs
mod common;

use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_update_check_shows_help() {
    let mut cmd = common::pipeguard_cmd();
    cmd.arg("update").arg("check").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Check for available updates"));
}

#[test]
fn test_update_status_shows_current_version() {
    let temp = tempdir().unwrap();

    // Create a mock active version
    let versions_dir = temp.path().join("versions/1.0.0");
    fs::create_dir_all(&versions_dir).unwrap();
    fs::write(versions_dir.join("core.yar"), b"rules").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs as unix_fs;
        unix_fs::symlink("versions/1.0.0", temp.path().join("active")).unwrap();
    }

    let mut cmd = common::pipeguard_cmd();
    cmd.arg("update")
        .arg("status")
        .arg("--storage")
        .arg(temp.path());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("1.0.0"));
}

#[test]
fn test_update_apply_requires_version() {
    let mut cmd = common::pipeguard_cmd();
    cmd.arg("update").arg("apply");

    // Should fail or show help when version not specified
    let output = cmd.output().unwrap();
    assert!(!output.status.success() || String::from_utf8_lossy(&output.stdout).contains("help"));
}

#[test]
fn test_update_rollback_requires_version() {
    let mut cmd = common::pipeguard_cmd();
    cmd.arg("update").arg("rollback");

    // Should fail or show help when version not specified
    let output = cmd.output().unwrap();
    assert!(!output.status.success() || String::from_utf8_lossy(&output.stdout).contains("help"));
}

#[test]
fn test_update_check_quiet_mode() {
    let mut cmd = common::pipeguard_cmd();
    cmd.arg("update").arg("check").arg("--quiet");

    // Should not crash with quiet flag
    // Exit codes: 0 = no updates/recently checked, 2 = error (network), 3 = update available
    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 2 || code == 3,
        "Unexpected exit code: {}",
        code
    );
}

#[test]
fn test_update_check_force_flag() {
    let mut cmd = common::pipeguard_cmd();
    cmd.arg("update").arg("check").arg("--force");

    // Should not crash with force flag
    // Exit codes: 0 = no updates, 2 = error (network), 3 = update available
    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 2 || code == 3,
        "Unexpected exit code: {}",
        code
    );
}

#[test]
fn test_update_cleanup_with_storage_path() {
    let temp = tempdir().unwrap();

    let mut cmd = common::pipeguard_cmd();
    cmd.arg("update")
        .arg("cleanup")
        .arg("--storage")
        .arg(temp.path());

    cmd.assert().success();
}
