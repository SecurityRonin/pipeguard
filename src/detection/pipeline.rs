//! Detection pipeline orchestration.

use crate::detection::scanner::{ScanError, YaraScanner};
use crate::detection::threat::{ThreatLevel, ThreatMatch, ThreatResponse};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

/// Pipeline configuration options.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Enable YARA scanning stage
    pub enable_yara: bool,
    /// Timeout for scanning in seconds
    pub timeout_secs: u32,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            enable_yara: true,
            timeout_secs: 60,
        }
    }
}

/// Errors from the detection pipeline.
#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("Scanner error: {0}")]
    ScannerError(#[from] ScanError),

    #[error("Failed to read rules directory: {0}")]
    RulesDirError(#[from] std::io::Error),

    #[error("No rules found in directory")]
    NoRulesFound,
}

/// Orchestrates multi-stage threat detection.
pub struct DetectionPipeline {
    scanner: YaraScanner,
    #[allow(dead_code)]
    config: PipelineConfig,
}

impl DetectionPipeline {
    /// Create a new pipeline from YARA rule source.
    pub fn new(rules: &str, config: PipelineConfig) -> Result<Self, PipelineError> {
        let scanner = YaraScanner::from_source(rules)?;
        Ok(Self { scanner, config })
    }

    /// Create a pipeline from a directory of .yar files.
    pub fn from_rules_dir(dir: &Path, config: PipelineConfig) -> Result<Self, PipelineError> {
        let mut combined_rules = String::new();

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "yar" || ext == "yara") {
                let content = std::fs::read_to_string(&path)?;
                combined_rules.push_str(&content);
                combined_rules.push('\n');
            }
        }

        if combined_rules.is_empty() {
            return Err(PipelineError::NoRulesFound);
        }

        Self::new(&combined_rules, config)
    }

    /// Analyze content for threats.
    pub fn analyze(&self, content: &str) -> Result<DetectionResult, PipelineError> {
        let scan_result = self.scanner.scan(content)?;
        let content_hash = compute_sha256(content);

        Ok(DetectionResult {
            matches: scan_result.matches().to_vec(),
            content_hash,
        })
    }
}

/// Result from the detection pipeline.
#[derive(Debug)]
pub struct DetectionResult {
    matches: Vec<ThreatMatch>,
    content_hash: String,
}

impl DetectionResult {
    /// Check if any threats were detected.
    pub fn is_threat(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Get the overall threat level.
    pub fn threat_level(&self) -> ThreatLevel {
        let max_score = ThreatMatch::max_score(&self.matches);
        ThreatLevel::from_score(max_score)
    }

    /// Get the recommended response action.
    pub fn recommended_response(&self) -> ThreatResponse {
        self.threat_level().default_response()
    }

    /// Get the number of rule matches.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Get the content hash (SHA-256).
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// Generate a human-readable report.
    pub fn report(&self) -> String {
        if self.matches.is_empty() {
            return "No threats detected.".to_string();
        }

        let mut report = format!(
            "Threat Level: {:?}\nMatches: {}\n\n",
            self.threat_level(),
            self.match_count()
        );

        for m in &self.matches {
            report.push_str(&format!(
                "- {} (severity {}): {}\n",
                m.rule_name(),
                m.severity(),
                m.description()
            ));
        }

        report
    }
}

fn compute_sha256(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}
