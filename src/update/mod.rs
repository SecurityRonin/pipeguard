// src/update/mod.rs
pub mod crypto;
pub mod manager;
pub mod storage;

pub use crypto::CryptoVerifier;
pub use manager::UpdateManager;
pub use storage::VersionedStorage;

/// Type alias for backward compatibility with tests.
pub type Storage = VersionedStorage;

#[derive(Debug, Clone)]
pub struct UpdateConfig {
    pub enabled: bool,
    pub auto_apply: bool,
    pub check_interval_hours: u64,
    pub source: String,
    pub keep_versions: usize,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_apply: false,
            check_interval_hours: 24,
            source: "https://github.com/SecurityRonin/pipeguard".to_string(),
            keep_versions: 3,
        }
    }
}

impl UpdateConfig {
    /// Validate the update source URL.
    ///
    /// Enforces:
    /// - HTTPS only (no HTTP, FTP, or other schemes)
    /// - Host must be exactly `github.com` (prevents SSRF to internal networks)
    /// - Path must contain `owner/repo` (at least two non-empty segments)
    /// - No embedded credentials
    /// - No path traversal sequences
    pub fn validate_source_url(&self) -> anyhow::Result<()> {
        let source = self.source.trim();
        if source.is_empty() {
            anyhow::bail!("Update source URL cannot be empty");
        }

        // Check for path traversal in raw string before URL normalization
        if source.contains("..") {
            anyhow::bail!("Update source URL contains path traversal sequences");
        }

        let url = url::Url::parse(source)
            .map_err(|e| anyhow::anyhow!("Invalid update source URL: {}", e))?;

        // Enforce HTTPS
        if url.scheme() != "https" {
            anyhow::bail!(
                "Update source must use HTTPS (got {}://). \
                 Plain HTTP is vulnerable to man-in-the-middle attacks.",
                url.scheme()
            );
        }

        // Reject embedded credentials
        if !url.username().is_empty() || url.password().is_some() {
            anyhow::bail!(
                "Update source URL must not contain credentials. \
                 Use environment variables for authentication."
            );
        }

        // Host must be exactly github.com
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Update source URL has no host"))?;
        if !host.eq_ignore_ascii_case("github.com") {
            anyhow::bail!(
                "Update source host must be github.com (got '{}').\n\
                 Only GitHub repositories are supported as update sources.",
                host
            );
        }

        // Path must have owner/repo (at least 2 non-empty segments)
        let path = url.path().trim_matches('/');
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 2 {
            anyhow::bail!(
                "Update source URL must specify owner/repo path (e.g., \
                 https://github.com/owner/repo)"
            );
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub version: String,
    pub severity: String,
    pub changelog: Vec<String>,
}
