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

#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub version: String,
    pub severity: String,
    pub changelog: Vec<String>,
}
