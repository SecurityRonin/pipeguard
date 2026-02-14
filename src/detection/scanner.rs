//! YARA-based script scanner.

use crate::detection::threat::{ThreatLevel, ThreatMatch};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
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

/// Holds either owned YARA rules or a shared cached reference.
enum CachedOrOwned {
    Owned(Rules),
    Cached(Arc<Rules>),
}

impl CachedOrOwned {
    fn as_rules(&self) -> &Rules {
        match self {
            CachedOrOwned::Owned(r) => r,
            CachedOrOwned::Cached(r) => r,
        }
    }
}

impl std::fmt::Debug for CachedOrOwned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CachedOrOwned::Owned(_) => write!(f, "Owned(Rules)"),
            CachedOrOwned::Cached(_) => write!(f, "Cached(Arc<Rules>)"),
        }
    }
}

/// YARA-based scanner for detecting malicious patterns.
pub struct YaraScanner {
    rules: CachedOrOwned,
    rule_count: usize,
    timeout_secs: u32,
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

        Ok(Self {
            rules: CachedOrOwned::Owned(rules),
            rule_count,
            timeout_secs: 60,
        })
    }

    /// Create a scanner from YARA rule source code with a custom timeout.
    pub fn from_source_with_timeout(source: &str, timeout_secs: u32) -> Result<Self, ScanError> {
        let mut scanner = Self::from_source(source)?;
        scanner.timeout_secs = timeout_secs;
        Ok(scanner)
    }

    /// Create a scanner from a YARA rule file.
    pub fn from_file(path: &Path) -> Result<Self, ScanError> {
        let source = std::fs::read_to_string(path)?;
        Self::from_source(&source)
    }

    /// Create a scanner using a shared rule cache.
    ///
    /// If rules for the given source are already compiled and cached,
    /// reuses the compiled rules instead of recompiling.
    pub fn from_cache(source: &str, cache: &RuleCache) -> Result<Self, ScanError> {
        let rules = cache.get_or_compile(source)?;
        let rule_count = count_yara_rules(source);
        Ok(Self {
            rules: CachedOrOwned::Cached(rules),
            rule_count,
            timeout_secs: 60,
        })
    }

    /// Get the number of rules loaded.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Get the scan timeout in seconds.
    pub fn timeout_secs(&self) -> u32 {
        self.timeout_secs
    }

    /// Set the scan timeout in seconds.
    pub fn set_timeout_secs(&mut self, timeout: u32) {
        self.timeout_secs = timeout;
    }

    /// Scan content for threats.
    pub fn scan(&self, content: &str) -> Result<ScanResult, ScanError> {
        let _span = debug_span!("yara_scan", rule_count = self.rule_count).entered();
        let timeout = if self.timeout_secs == 0 {
            0 // YARA treats 0 as no timeout
        } else {
            self.timeout_secs as i32
        };
        let yara_matches = self
            .rules
            .as_rules()
            .scan_mem(content.as_bytes(), timeout)
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
                    yara::MetadataValue::String(s) => Some(s),
                    _ => None,
                })
                .map_or("No description", |v| v);

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

/// Thread-safe cache for compiled YARA rules.
///
/// Uses the SHA-256 hash of rule source text as cache key to avoid
/// recompiling unchanged rules.
pub struct RuleCache {
    cache: Mutex<HashMap<String, Arc<Rules>>>,
}

impl RuleCache {
    /// Create a new empty rule cache.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get compiled rules from cache, or compile and cache them.
    pub fn get_or_compile(&self, source: &str) -> Result<Arc<Rules>, ScanError> {
        let key = Self::cache_key(source);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(rules) = cache.get(&key) {
            debug!("Rule cache hit");
            return Ok(Arc::clone(rules));
        }

        debug!("Rule cache miss, compiling");
        let compiler = Compiler::new()
            .map_err(|e| ScanError::CompileError(e.to_string()))?
            .add_rules_str(source)
            .map_err(|e| ScanError::CompileError(e.to_string()))?;

        let rules = compiler
            .compile_rules()
            .map_err(|e| ScanError::CompileError(e.to_string()))?;

        let arc_rules = Arc::new(rules);
        cache.insert(key, Arc::clone(&arc_rules));
        Ok(arc_rules)
    }

    fn cache_key(source: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(source.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl Default for RuleCache {
    fn default() -> Self {
        Self::new()
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
            let after_keyword = trimmed
                .strip_prefix("rule ")
                .or_else(|| trimmed.strip_prefix("private rule "))
                .or_else(|| trimmed.strip_prefix("global rule "));
            // Verify the next token looks like a valid identifier (starts with alpha/underscore)
            after_keyword
                .map(|rest| rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
                .unwrap_or(false)
        })
        .count()
}
