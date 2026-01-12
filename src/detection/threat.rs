//! Threat level classification and response mapping.

use serde::{Deserialize, Serialize};

/// Severity level of a detected threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    /// No threat detected (score 0)
    None,
    /// Low severity threat (scores 1-6) - suspicious but likely benign
    Low,
    /// Medium severity threat (scores 7-8) - significant risk indicators
    Medium,
    /// High severity threat (scores 9-10) - known malware or critical IOCs
    High,
}

impl ThreatLevel {
    /// Convert a numeric severity score (0-10) to a threat level.
    pub fn from_score(score: u8) -> Self {
        match score {
            0 => ThreatLevel::None,
            1..=6 => ThreatLevel::Low,
            7..=8 => ThreatLevel::Medium,
            9..=10 => ThreatLevel::High,
            _ => ThreatLevel::High, // Anything above 10 is still High
        }
    }

    /// Get the default response action for this threat level.
    pub fn default_response(&self) -> ThreatResponse {
        match self {
            ThreatLevel::None => ThreatResponse::Allow,
            ThreatLevel::Low => ThreatResponse::Warn,
            ThreatLevel::Medium => ThreatResponse::Prompt,
            ThreatLevel::High => ThreatResponse::Block,
        }
    }
}

/// Response action to take for a detected threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatResponse {
    /// Allow execution without intervention
    Allow,
    /// Warn the user but allow execution
    Warn,
    /// Prompt user for confirmation before execution
    Prompt,
    /// Block execution entirely
    Block,
}

/// A single threat match from detection.
#[derive(Debug, Clone)]
pub struct ThreatMatch {
    rule_name: String,
    severity: u8,
    description: String,
}

impl ThreatMatch {
    /// Create a new threat match.
    pub fn new(rule_name: &str, severity: u8, description: &str) -> Self {
        Self {
            rule_name: rule_name.to_string(),
            severity,
            description: description.to_string(),
        }
    }

    /// Get the rule name that triggered this match.
    pub fn rule_name(&self) -> &str {
        &self.rule_name
    }

    /// Get the severity score (0-10).
    pub fn severity(&self) -> u8 {
        self.severity
    }

    /// Get the human-readable description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the maximum severity score from a list of matches.
    pub fn max_score(matches: &[ThreatMatch]) -> u8 {
        matches.iter().map(|m| m.severity).max().unwrap_or(0)
    }
}
