// Tests for audit log with size limits and rotation
// Covers: creation, writing, size limits, rotation, DoS prevention

use pipeguard::logging::audit::{AuditConfig, AuditLog};
use std::fs;
use tempfile::TempDir;

// ─── Creation ───────────────────────────────────────────────────

#[test]
fn audit_log_creates_file() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("audit.log");
    let _log = AuditLog::open(&path, AuditConfig::default()).unwrap();
    assert!(path.exists());
}

#[test]
fn audit_log_creates_parent_dirs() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("subdir/nested/audit.log");
    let _log = AuditLog::open(&path, AuditConfig::default()).unwrap();
    assert!(path.exists());
}

// ─── Writing ────────────────────────────────────────────────────

#[test]
fn audit_log_writes_entry() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("audit.log");
    let log = AuditLog::open(&path, AuditConfig::default()).unwrap();

    log.record("scan", "Scanned input from stdin").unwrap();

    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("scan"), "Should contain event type");
    assert!(
        content.contains("Scanned input from stdin"),
        "Should contain message"
    );
}

#[test]
fn audit_log_appends_multiple_entries() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("audit.log");
    let log = AuditLog::open(&path, AuditConfig::default()).unwrap();

    log.record("scan", "First scan").unwrap();
    log.record("update", "Updated rules").unwrap();
    log.record("threat", "Threat detected").unwrap();

    let content = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3, "Should have 3 log entries");
}

#[test]
fn audit_log_entries_are_json() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("audit.log");
    let log = AuditLog::open(&path, AuditConfig::default()).unwrap();

    log.record("scan", "test message").unwrap();

    let content = fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed["event"], "scan");
    assert_eq!(parsed["message"], "test message");
    assert!(parsed["timestamp"].is_string(), "Should have timestamp");
}

// ─── Size limits ────────────────────────────────────────────────

#[test]
fn audit_log_rotates_when_exceeding_max_size() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("audit.log");
    let config = AuditConfig {
        max_file_bytes: 200, // Very small limit to trigger rotation
        max_rotated_files: 3,
    };
    let log = AuditLog::open(&path, config).unwrap();

    // Write enough to exceed 200 bytes
    for i in 0..20 {
        log.record("scan", &format!("Entry number {}", i)).unwrap();
    }

    // Rotated file should exist
    let rotated = temp.path().join("audit.log.1");
    assert!(
        rotated.exists(),
        "Should create rotated file when exceeding max size"
    );
}

#[test]
fn audit_log_limits_rotated_files() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("audit.log");
    let config = AuditConfig {
        max_file_bytes: 100,
        max_rotated_files: 2,
    };
    let log = AuditLog::open(&path, config).unwrap();

    // Write lots of entries to trigger multiple rotations
    for i in 0..100 {
        log.record("scan", &format!("Entry {}", i)).unwrap();
    }

    // Should have at most 2 rotated files + the active file
    let audit_log_3 = temp.path().join("audit.log.3");
    assert!(
        !audit_log_3.exists(),
        "Should not keep more than max_rotated_files"
    );
}

// ─── DoS prevention ────────────────────────────────────────────

#[test]
fn audit_log_handles_large_messages_gracefully() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("audit.log");
    let config = AuditConfig {
        max_file_bytes: 10_000,
        max_rotated_files: 2,
    };
    let log = AuditLog::open(&path, config).unwrap();

    // Attempt a very large message (1MB)
    let large_msg = "x".repeat(1_000_000);
    let result = log.record("scan", &large_msg);

    // Should either succeed (and rotate) or truncate, but not OOM/panic
    // The important thing is it doesn't crash
    drop(result);
}

#[test]
fn audit_log_total_disk_bounded() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("audit.log");
    let config = AuditConfig {
        max_file_bytes: 500,
        max_rotated_files: 3,
    };
    let log = AuditLog::open(&path, config).unwrap();

    // Write a lot of data
    for i in 0..200 {
        log.record("scan", &format!("Entry {}", i)).unwrap();
    }

    // Total size across all audit files should be bounded
    let total: u64 = fs::read_dir(temp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit.log"))
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum();

    // Max total = max_file_bytes * (max_rotated_files + 1) + some overhead
    let max_expected = 500 * (3 + 1) + 2000; // generous overhead for JSON wrapping
    assert!(
        total < max_expected,
        "Total audit log size ({} bytes) should be bounded (max {})",
        total,
        max_expected
    );
}

// ─── Config defaults ────────────────────────────────────────────

#[test]
fn audit_config_defaults_are_reasonable() {
    let config = AuditConfig::default();
    assert_eq!(config.max_file_bytes, 10 * 1024 * 1024); // 10MB
    assert_eq!(config.max_rotated_files, 5);
}
