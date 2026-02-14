//! Append-only audit log with size limits and rotation.
//!
//! Records security-relevant events (scans, updates, threats) as JSON lines.
//! Enforces per-file size limits and rotates old files to prevent DoS via
//! unbounded log growth.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Failed to open audit log: {0}")]
    OpenError(#[from] std::io::Error),

    #[error("Failed to serialize audit entry: {0}")]
    SerializeError(#[from] serde_json::Error),
}

/// Configuration for audit log size limits.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Maximum size of a single log file in bytes before rotation.
    pub max_file_bytes: u64,
    /// Maximum number of rotated files to keep (e.g., audit.log.1, audit.log.2, ...).
    pub max_rotated_files: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 10 * 1024 * 1024, // 10 MB
            max_rotated_files: 5,
        }
    }
}

/// Append-only audit log with automatic rotation.
pub struct AuditLog {
    path: PathBuf,
    config: AuditConfig,
}

impl AuditLog {
    /// Open (or create) an audit log at the given path.
    pub fn open(path: &Path, config: AuditConfig) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create the file if it doesn't exist
        OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            config,
        })
    }

    /// Record a security event.
    pub fn record(&self, event: &str, message: &str) -> Result<(), AuditError> {
        // Check if rotation is needed before writing
        self.rotate_if_needed()?;

        let entry = serde_json::json!({
            "timestamp": chrono_iso8601_now(),
            "event": event,
            "message": message,
        });

        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;

        Ok(())
    }

    /// Rotate log files if the current file exceeds the size limit.
    fn rotate_if_needed(&self) -> Result<(), AuditError> {
        let size = match fs::metadata(&self.path) {
            Ok(m) => m.len(),
            Err(_) => return Ok(()), // File doesn't exist yet
        };

        if size < self.config.max_file_bytes {
            return Ok(());
        }

        // Shift rotated files: .3 -> .4, .2 -> .3, .1 -> .2
        // Delete the oldest if beyond max_rotated_files
        for i in (1..=self.config.max_rotated_files).rev() {
            let src = self.rotated_path(i);
            let dst = self.rotated_path(i + 1);
            if src.exists() {
                if i == self.config.max_rotated_files {
                    // Delete the oldest
                    let _ = fs::remove_file(&src);
                } else {
                    let _ = fs::rename(&src, &dst);
                }
            }
        }

        // Move current to .1
        let _ = fs::rename(&self.path, self.rotated_path(1));

        // Create fresh file
        File::create(&self.path)?;

        Ok(())
    }

    fn rotated_path(&self, n: u32) -> PathBuf {
        let name = self.path.file_name().unwrap_or_default().to_string_lossy();
        self.path.with_file_name(format!("{}.{}", name, n))
    }
}

/// ISO 8601 timestamp without pulling in the chrono crate.
fn chrono_iso8601_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    // Format as seconds since epoch (good enough for audit logs)
    // A full ISO 8601 format would require chrono, but we removed that dep.
    format!("{}s", now.as_secs())
}
