// src/update/storage.rs
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

#[derive(Debug)]
pub struct VersionedStorage {
    root: PathBuf,
}

impl VersionedStorage {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).context("Failed to create storage root directory")?;
        fs::create_dir_all(root.join("versions")).context("Failed to create versions directory")?;

        Ok(Self { root })
    }

    /// Create a new version directory (alias for create_version_dir)
    pub fn create_version(&self, version: &str) -> Result<PathBuf> {
        self.create_version_dir(version)
    }

    /// Validate version string to prevent path traversal
    fn validate_version(version: &str) -> Result<()> {
        if version.contains("..")
            || version.contains('/')
            || version.contains('\\')
            || version.contains('\0')
            || version.is_empty()
        {
            anyhow::bail!(
                "Invalid version string '{}': must not contain path separators, '..' or null bytes",
                version
            );
        }
        Ok(())
    }

    /// Create a new version directory
    pub fn create_version_dir(&self, version: &str) -> Result<PathBuf> {
        Self::validate_version(version)?;
        let version_path = self.root.join("versions").join(version);
        fs::create_dir_all(&version_path).context("Failed to create version directory")?;
        debug!(version = version, "Created version directory");
        Ok(version_path)
    }

    /// Write rules to version directory
    pub fn write_rules(&self, version_path: &Path, rules: &[u8]) -> Result<()> {
        let rules_file = version_path.join("core.yar");
        fs::write(rules_file, rules).context("Failed to write rules file")?;
        Ok(())
    }

    /// Read rules from version directory
    pub fn read_rules(&self, version_path: &Path) -> Result<Vec<u8>> {
        let rules_file = version_path.join("core.yar");
        fs::read(rules_file).context("Failed to read rules file")
    }

    /// Atomically activate a version by updating the symlink.
    /// Requires the version to exist and be verified.
    pub fn activate_version(&self, version: &str) -> Result<()> {
        if !self.has_version(version) {
            anyhow::bail!("Version {} does not exist", version);
        }
        if !self.is_verified(version)? {
            anyhow::bail!("Version {} is not verified - refusing to activate", version);
        }

        let target = PathBuf::from("versions").join(version);
        let link_path = self.root.join("active");
        let temp_link = self.root.join(format!(
            ".active.tmp.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        // Remove temp link if it exists from previous failed attempt
        let _ = fs::remove_file(&temp_link);

        // Create temp symlink
        #[cfg(unix)]
        {
            use std::os::unix::fs as unix_fs;
            unix_fs::symlink(&target, &temp_link).context("Failed to create temporary symlink")?;
        }

        #[cfg(not(unix))]
        {
            anyhow::bail!("Symlinks only supported on Unix platforms");
        }

        // Atomically rename (this is atomic on Unix)
        fs::rename(&temp_link, &link_path).context("Failed to activate version")?;

        debug!(version = version, "Symlink updated to version");
        Ok(())
    }

    /// Get currently active version, or None if no version is active
    pub fn current_version(&self) -> Result<Option<String>> {
        let link_path = self.root.join("active");
        match fs::read_link(&link_path) {
            Ok(target) => {
                let version = target
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string());
                Ok(version)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to read active symlink: {}", e)),
        }
    }

    /// Check if version exists
    pub fn has_version(&self, version: &str) -> bool {
        self.root.join("versions").join(version).exists()
    }

    /// Get the path to a specific version directory
    pub fn version_path(&self, version: &str) -> Result<PathBuf> {
        let path = self.root.join("versions").join(version);
        if !path.exists() {
            anyhow::bail!("Version {} does not exist", version);
        }
        Ok(path)
    }

    /// Mark a version as verified by creating the .verified marker
    pub fn mark_verified(&self, version: &str) -> Result<()> {
        let marker = self.root.join("versions").join(version).join(".verified");
        fs::write(&marker, "").context("Failed to create verification marker")?;
        Ok(())
    }

    /// Check if version has .verified marker
    pub fn is_verified(&self, version: &str) -> Result<bool> {
        let marker = self.root.join("versions").join(version).join(".verified");
        Ok(marker.exists())
    }

    /// List all version directories
    pub fn list_versions(&self) -> Result<Vec<String>> {
        let versions_dir = self.root.join("versions");
        let mut versions = Vec::new();
        for entry in fs::read_dir(&versions_dir)? {
            let entry = entry?;
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    versions.push(name.to_string());
                }
            }
        }
        Ok(versions)
    }

    /// Cleanup old versions, keeping only the latest N
    pub fn cleanup_old_versions(&self, keep: usize) -> Result<()> {
        let versions_dir = self.root.join("versions");
        let mut versions: Vec<_> = fs::read_dir(&versions_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();

        // Sort by modification time (newest first)
        versions
            .sort_by_key(|e| std::cmp::Reverse(e.metadata().ok().and_then(|m| m.modified().ok())));

        // Remove versions beyond keep limit
        for entry in versions.iter().skip(keep) {
            fs::remove_dir_all(entry.path()).context("Failed to remove old version")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_creation() {
        let temp = tempdir().unwrap();
        let result = VersionedStorage::new(temp.path().to_path_buf());
        assert!(result.is_ok());
    }
}
