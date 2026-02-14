//! YARA-based script scanner.

use crate::detection::threat::{ThreatLevel, ThreatMatch};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, debug_span};
use yara::{Compiler, Rules};

/// Errors that can occur during scanning.
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Failed to compile YARA rules: {0}")]
    CompileError(String),

    #[error("Failed to read rule file: {0}")]
    FileError(#[from] std::io::Error),

    #[error("Failed to scan content: {0}")]
    ScanError(String),
}

/// YARA-based scanner for detecting malicious patterns.
pub struct YaraScanner {
    rules: Rules,
    rule_count: usize,
}

impl std::fmt::Debug for YaraScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraScanner")
            .field("rule_count", &self.rule_count)
            .finish_non_exhaustive()
    }
}

impl YaraScanner {
    /// Create a scanner from YARA rule source code.
    pub fn from_source(source: &str) -> Result<Self, ScanError> {
        let compiler = Compiler::new()
            .map_err(|e| ScanError::CompileError(e.to_string()))?
            .add_rules_str(source)
            .map_err(|e| ScanError::CompileError(e.to_string()))?;

        let rules = compiler
            .compile_rules()
            .map_err(|e| ScanError::CompileError(e.to_string()))?;

        // Count rule declarations in source (YARA Rules doesn't expose a count)
        let rule_count = count_yara_rules(source);

        Ok(Self { rules, rule_count })
    }

    /// Create a scanner from a YARA rule file.
    pub fn from_file(path: &Path) -> Result<Self, ScanError> {
        let source = std::fs::read_to_string(path)?;
        Self::from_source(&source)
    }

    /// Get the number of rules loaded.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Scan content for threats.
    pub fn scan(&self, content: &str) -> Result<ScanResult, ScanError> {
        let _span = debug_span!("yara_scan", rule_count = self.rule_count).entered();
        let yara_matches = self
            .rules
            .scan_mem(content.as_bytes(), 60)
            .map_err(|e| ScanError::ScanError(e.to_string()))?;
        debug!(match_count = yara_matches.len(), "YARA scan complete");

        let mut matches = Vec::new();

        for m in yara_matches {
            // Extract metadata
            let severity = m
                .metadatas
                .iter()
                .find(|meta| meta.identifier == "severity")
                .and_then(|meta| match meta.value {
                    yara::MetadataValue::Integer(v) => Some(v as u8),
                    _ => None,
                })
                .unwrap_or(5); // Default severity

            let description = m
                .metadatas
                .iter()
                .find(|meta| meta.identifier == "description")
                .and_then(|meta| match &meta.value {
                    yara::MetadataValue::String(s) => Some(s.as_ref()),
                    _ => None,
                })
                .unwrap_or("No description");

            matches.push(ThreatMatch::new(m.identifier, severity, description));
        }

        Ok(ScanResult { matches })
    }
}

/// Result of scanning content.
#[derive(Debug)]
pub struct ScanResult {
    matches: Vec<ThreatMatch>,
}

impl ScanResult {
    /// Check if any matches were found.
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Get all threat matches.
    pub fn matches(&self) -> &[ThreatMatch] {
        &self.matches
    }

    /// Get the overall threat level based on highest severity match.
    pub fn threat_level(&self) -> ThreatLevel {
        let max_score = ThreatMatch::max_score(&self.matches);
        ThreatLevel::from_score(max_score)
    }
}

/// Count YARA rule declarations in source text.
///
/// Matches lines starting with optional whitespace followed by
/// `rule <identifier>` (possibly with tags/modifiers before `{`).
fn count_yara_rules(source: &str) -> usize {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            // Match "rule <name>" or "private rule <name>" or "global rule <name>"
            let after_keyword = if let Some(rest) = trimmed.strip_prefix("rule ") {
                Some(rest)
            } else if let Some(rest) = trimmed.strip_prefix("private rule ") {
                Some(rest)
            } else if let Some(rest) = trimmed.strip_prefix("global rule ") {
                Some(rest)
            } else {
                None
            };
            // Verify the next token looks like a valid identifier (starts with alpha/underscore)
            after_keyword
                .map(|rest| rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
                .unwrap_or(false)
        })
        .count()
}
