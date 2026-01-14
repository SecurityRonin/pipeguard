// src/update/storage.rs
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub struct VersionedStorage {
    root: PathBuf,
}

impl VersionedStorage {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .context("Failed to create storage root directory")?;
        fs::create_dir_all(root.join("versions"))
            .context("Failed to create versions directory")?;

        Ok(Self { root })
    }

    /// Create a new version directory
    pub fn create_version_dir(&self, version: &str) -> Result<PathBuf> {
        let version_path = self.root.join("versions").join(version);
        fs::create_dir_all(&version_path)
            .context("Failed to create version directory")?;
        Ok(version_path)
    }

    /// Write rules to version directory
    pub fn write_rules(&self, version_path: &Path, rules: &[u8]) -> Result<()> {
        let rules_file = version_path.join("core.yar");
        fs::write(rules_file, rules)
            .context("Failed to write rules file")?;
        Ok(())
    }

    /// Read rules from version directory
    pub fn read_rules(&self, version_path: &Path) -> Result<Vec<u8>> {
        let rules_file = version_path.join("core.yar");
        fs::read(rules_file)
            .context("Failed to read rules file")
    }

    /// Atomically activate a version by updating the symlink
    pub fn activate_version(&self, version: &str) -> Result<()> {
        let target = PathBuf::from("versions").join(version);
        let link_path = self.root.join("active");
        let temp_link = self.root.join(".active.tmp");

        // Remove temp link if it exists from previous failed attempt
        let _ = fs::remove_file(&temp_link);

        // Create temp symlink
        #[cfg(unix)]
        {
            use std::os::unix::fs as unix_fs;
            unix_fs::symlink(&target, &temp_link)
                .context("Failed to create temporary symlink")?;
        }

        #[cfg(not(unix))]
        {
            anyhow::bail!("Symlinks only supported on Unix platforms");
        }

        // Atomically rename (this is atomic on Unix)
        fs::rename(&temp_link, &link_path)
            .context("Failed to activate version")?;

        Ok(())
    }

    /// Get currently active version
    pub fn current_version(&self) -> Result<String> {
        let link_path = self.root.join("active");
        let target = fs::read_link(&link_path)
            .context("No active version set")?;

        let version = target.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid version path"))?;

        Ok(version.to_string())
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

    /// Check if version has .verified marker
    pub fn is_verified(&self, version: &str) -> Result<bool> {
        let marker = self.root.join("versions").join(version).join(".verified");
        Ok(marker.exists())
    }

    /// Cleanup old versions, keeping only the latest N
    pub fn cleanup_old_versions(&self, keep: usize) -> Result<()> {
        let versions_dir = self.root.join("versions");
        let mut versions: Vec<_> = fs::read_dir(&versions_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();

        // Sort by modification time (newest first)
        versions.sort_by_key(|e| std::cmp::Reverse(
            e.metadata().ok().and_then(|m| m.modified().ok())
        ));

        // Remove versions beyond keep limit
        for entry in versions.iter().skip(keep) {
            fs::remove_dir_all(entry.path())
                .context("Failed to remove old version")?;
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
