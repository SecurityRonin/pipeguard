//! Configuration management for PipeGuard.

use crate::detection::threat::{ThreatLevel, ThreatResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Configuration errors.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Failed to serialize config: {0}")]
    SerializeError(#[from] toml::ser::Error),
}

/// Main configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub detection: DetectionConfig,
    pub response: ResponseConfig,
    pub rules: RulesConfig,
    pub allowlist: AllowlistConfig,
    pub updates: UpdatesConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            detection: DetectionConfig::default(),
            response: ResponseConfig::default(),
            rules: RulesConfig::default(),
            allowlist: AllowlistConfig::default(),
            updates: UpdatesConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Get the default configuration file path.
    pub fn default_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("pipeguard")
            .join("config.toml")
    }

    /// Get the response action for a given threat level.
    pub fn response_for(&self, level: ThreatLevel) -> ThreatResponse {
        match level {
            ThreatLevel::None => ThreatResponse::Allow,
            ThreatLevel::Low => self.response.low,
            ThreatLevel::Medium => self.response.medium,
            ThreatLevel::High => self.response.high,
        }
    }

    /// Check if a content hash is in the allowlist.
    pub fn is_allowlisted_hash(&self, hash: &str) -> bool {
        self.allowlist.hashes.contains(hash)
    }

    /// Check if a domain is in the allowlist.
    pub fn is_allowlisted_domain(&self, domain: &str) -> bool {
        self.allowlist.domains.contains(domain)
    }

    /// Serialize configuration to TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }
}

/// Detection stage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    pub enable_yara: bool,
    pub enable_sandbox: bool,
    pub timeout_secs: u32,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enable_yara: true,
            enable_sandbox: true,
            timeout_secs: 60,
        }
    }
}

/// Response action configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseConfig {
    #[serde(with = "threat_response_serde")]
    pub low: ThreatResponse,
    #[serde(with = "threat_response_serde")]
    pub medium: ThreatResponse,
    #[serde(with = "threat_response_serde")]
    pub high: ThreatResponse,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            low: ThreatResponse::Warn,
            medium: ThreatResponse::Prompt,
            high: ThreatResponse::Block,
        }
    }
}

/// Rules configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RulesConfig {
    pub custom_rules_path: Option<String>,
}

/// Allowlist configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AllowlistConfig {
    #[serde(default)]
    hashes: HashSet<String>,
    #[serde(default)]
    domains: HashSet<String>,
}

/// Updates configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdatesConfig {
    /// Enable automatic update checks
    pub enabled: bool,
    /// Automatically apply verified updates
    pub auto_apply: bool,
    /// Check interval in hours
    pub check_interval_hours: u64,
    /// GitHub repository for updates
    pub source: String,
    /// Number of versions to keep
    pub keep_versions: usize,
}

impl Default for UpdatesConfig {
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

/// Helper for response override parsing.
pub struct ResponseOverride;

impl ResponseOverride {
    pub fn from_str(s: &str) -> Option<ThreatResponse> {
        match s.to_lowercase().as_str() {
            "allow" => Some(ThreatResponse::Allow),
            "warn" => Some(ThreatResponse::Warn),
            "prompt" => Some(ThreatResponse::Prompt),
            "block" => Some(ThreatResponse::Block),
            _ => None,
        }
    }
}

/// Serde helper for ThreatResponse.
mod threat_response_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(response: &ThreatResponse, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match response {
            ThreatResponse::Allow => "allow",
            ThreatResponse::Warn => "warn",
            ThreatResponse::Prompt => "prompt",
            ThreatResponse::Block => "block",
        };
        serializer.serialize_str(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ThreatResponse, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ResponseOverride::from_str(&s).ok_or_else(|| {
            serde::de::Error::custom(format!("invalid response type: {}", s))
        })
    }
}
