// src/update/manager.rs
use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{debug, info};

use super::{CryptoVerifier, UpdateConfig, VersionedStorage};

#[derive(Debug)]
pub struct UpdateManager {
    storage: VersionedStorage,
    #[allow(dead_code)]
    verifier: CryptoVerifier,
    config: UpdateConfig,
}

impl UpdateManager {
    pub fn new(root: PathBuf, config: UpdateConfig) -> Result<Self> {
        let storage =
            VersionedStorage::new(root).context("Failed to initialize versioned storage")?;
        let verifier = CryptoVerifier::new().context("Failed to initialize crypto verifier")?;

        Ok(Self {
            storage,
            verifier,
            config,
        })
    }

    /// Check if updates are available by querying GitHub Releases API
    pub fn check_for_updates(&self) -> Result<Option<String>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let latest = self.fetch_latest_release()?;

        match self.storage.current_version()? {
            Some(current) if current == latest => Ok(None),
            _ => Ok(Some(latest)),
        }
    }

    /// Fetch the latest release version tag from GitHub
    fn fetch_latest_release(&self) -> Result<String> {
        let api_base = self.github_api_url()?;
        let url = format!("{}/releases/latest", api_base);
        debug!(url = %url, "Fetching latest release");

        let client = reqwest::blocking::Client::builder()
            .user_agent("pipeguard-updater")
            .build()?;

        let resp: serde_json::Value = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()?
            .error_for_status()
            .context("GitHub API request failed")?
            .json()?;

        let tag = resp["tag_name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No tag_name in release response"))?;

        let version = tag.strip_prefix('v').unwrap_or(tag);
        Ok(version.to_string())
    }

    /// Convert GitHub web URL to API URL
    /// e.g. "https://github.com/SecurityRonin/pipeguard" -> "https://api.github.com/repos/SecurityRonin/pipeguard"
    fn github_api_url(&self) -> Result<String> {
        let source = self.config.source.trim_end_matches('/');
        let path = source
            .strip_prefix("https://github.com/")
            .or_else(|| source.strip_prefix("http://github.com/"))
            .ok_or_else(|| anyhow::anyhow!("Source URL is not a GitHub URL: {}", source))?;
        Ok(format!("https://api.github.com/repos/{}", path))
    }

    /// Download rules and signature from a GitHub release
    pub fn download_rules(&self, version: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let tag = format!("v{}", version);
        let base_url = format!(
            "{}/releases/download/{}",
            self.config.source.trim_end_matches('/'),
            tag
        );

        let client = reqwest::blocking::Client::builder()
            .user_agent("pipeguard-updater")
            .build()?;

        debug!(version = version, "Downloading rules");

        let rules = client
            .get(format!("{}/core.yar", base_url))
            .send()?
            .error_for_status()
            .context("Failed to download rules")?
            .bytes()?
            .to_vec();

        let signature = client
            .get(format!("{}/core.yar.sig", base_url))
            .send()?
            .error_for_status()
            .context("Failed to download signature")?
            .bytes()?
            .to_vec();

        info!(
            version = version,
            rules_bytes = rules.len(),
            "Rules downloaded"
        );
        Ok((rules, signature))
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
        self.storage
            .activate_version(version)
            .context("Failed to activate version")?;

        info!(version = version, "Version activated");
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

        self.storage
            .activate_version(version)
            .context("Failed to rollback to version")?;

        info!(version = version, "Rolled back to version");
        Ok(())
    }

    /// Cleanup old versions according to config
    pub fn cleanup(&self) -> Result<()> {
        debug!("Running version cleanup");
        self.storage
            .cleanup_old_versions(self.config.keep_versions)
            .context("Failed to cleanup old versions")
    }

    /// Get currently active version
    pub fn current_version(&self) -> Result<Option<String>> {
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

    #[test]
    fn check_for_updates_disabled_returns_none() {
        let temp = tempdir().unwrap();
        let config = UpdateConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();
        assert_eq!(manager.check_for_updates().unwrap(), None);
    }

    #[test]
    fn github_api_url_conversion() {
        let temp = tempdir().unwrap();
        let config = UpdateConfig {
            source: "https://github.com/SecurityRonin/pipeguard".to_string(),
            ..Default::default()
        };
        let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();
        assert_eq!(
            manager.github_api_url().unwrap(),
            "https://api.github.com/repos/SecurityRonin/pipeguard"
        );
    }

    #[test]
    fn github_api_url_strips_trailing_slash() {
        let temp = tempdir().unwrap();
        let config = UpdateConfig {
            source: "https://github.com/SecurityRonin/pipeguard/".to_string(),
            ..Default::default()
        };
        let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();
        assert_eq!(
            manager.github_api_url().unwrap(),
            "https://api.github.com/repos/SecurityRonin/pipeguard"
        );
    }

    #[test]
    fn github_api_url_rejects_non_github() {
        let temp = tempdir().unwrap();
        let config = UpdateConfig {
            source: "https://gitlab.com/foo/bar".to_string(),
            ..Default::default()
        };
        let manager = UpdateManager::new(temp.path().to_path_buf(), config).unwrap();
        assert!(manager.github_api_url().is_err());
    }
}
