// src/update/manager.rs
use anyhow::{Context, Result};
use std::path::PathBuf;

use super::{UpdateConfig, CryptoVerifier, VersionedStorage};

pub struct UpdateManager {
    storage: VersionedStorage,
    verifier: CryptoVerifier,
    config: UpdateConfig,
}

impl UpdateManager {
    pub fn new(root: PathBuf, config: UpdateConfig) -> Result<Self> {
        let storage = VersionedStorage::new(root)
            .context("Failed to initialize versioned storage")?;
        let verifier = CryptoVerifier::new()
            .context("Failed to initialize crypto verifier")?;

        Ok(Self {
            storage,
            verifier,
            config,
        })
    }

    /// Check if updates are available
    pub fn check_for_updates(&self) -> Result<Option<String>> {
        if !self.config.enabled {
            return Ok(None);
        }

        // For now, just check if there's no active version
        // In real implementation, this would query GitHub Releases API
        match self.storage.current_version() {
            Ok(_) => Ok(None), // Already have a version
            Err(_) => Ok(Some("latest".to_string())), // No active version
        }
    }

    /// Download rules for a specific version
    ///
    /// In real implementation, this would:
    /// 1. Query GitHub Releases API for version
    /// 2. Download core.yar and core.yar.sig
    /// 3. Return (rules_bytes, signature_bytes)
    pub fn download_rules(&self, version: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        // Stub implementation for testing
        anyhow::bail!("GitHub API integration not yet implemented for version {}", version)
    }

    /// Apply an update by activating a verified version
    pub fn apply_update(&self, version: &str) -> Result<()> {
        // Verify the version exists and is verified
        if !self.storage.has_version(version) {
            anyhow::bail!("Version {} does not exist", version);
        }

        if !self.storage.is_verified(version)? {
            anyhow::bail!("Version {} is not verified - refusing to activate", version);
        }

        // Activate the version
        self.storage.activate_version(version)
            .context("Failed to activate version")?;

        Ok(())
    }

    /// Rollback to a previous version
    pub fn rollback(&self, version: &str) -> Result<()> {
        if !self.storage.has_version(version) {
            anyhow::bail!("Cannot rollback to non-existent version {}", version);
        }

        if !self.storage.is_verified(version)? {
            anyhow::bail!("Cannot rollback to unverified version {}", version);
        }

        self.storage.activate_version(version)
            .context("Failed to rollback to version")?;

        Ok(())
    }

    /// Cleanup old versions according to config
    pub fn cleanup(&self) -> Result<()> {
        self.storage.cleanup_old_versions(self.config.keep_versions)
            .context("Failed to cleanup old versions")
    }

    /// Get currently active version
    pub fn current_version(&self) -> Result<String> {
        self.storage.current_version()
    }

    /// Check if version exists
    pub fn has_version(&self, version: &str) -> bool {
        self.storage.has_version(version)
    }

    /// Process an update (download, verify, and optionally apply)
    ///
    /// This orchestrates the full update workflow:
    /// 1. Download rules and signature
    /// 2. Verify signature
    /// 3. Store in versioned directory
    /// 4. Mark as verified
    /// 5. Apply if auto_apply is enabled
    pub fn process_update(&self, version: &str) -> Result<()> {
        // For now, assume version is already downloaded and verified
        // In real implementation, this would call download_rules() and verify

        if self.config.auto_apply {
            self.apply_update(version)
                .context("Failed to auto-apply update")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_manager_creation() {
        let temp = tempdir().unwrap();
        let config = UpdateConfig::default();
        let result = UpdateManager::new(temp.path().to_path_buf(), config);
        assert!(result.is_ok(), "UpdateManager creation should succeed");
    }
}
