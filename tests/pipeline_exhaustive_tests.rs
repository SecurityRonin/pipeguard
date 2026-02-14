//! Exhaustive tests for detection pipeline.

use pipeguard::detection::pipeline::{DetectionPipeline, PipelineConfig};
use pipeguard::detection::threat::{ThreatLevel, ThreatResponse};
use std::fs;
use tempfile::TempDir;

// =============================================================================
// Pipeline creation tests
// =============================================================================

#[test]
fn create_pipeline_with_valid_rules() {
    let rules = r#"
        rule test { meta: severity = 5 description = "test" condition: true }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default());
    assert!(pipeline.is_ok());
}

#[test]
fn create_pipeline_with_invalid_rules() {
    let rules = "invalid syntax {{{";
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default());
    assert!(pipeline.is_err());
}

#[test]
fn create_pipeline_with_empty_rules() {
    // YARA accepts empty rules as valid (no rules means no matches)
    let rules = "";
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default());
    assert!(pipeline.is_ok());
}

#[test]
fn create_pipeline_with_custom_config() {
    let config = PipelineConfig {
        enable_yara: true,
        timeout_secs: 120,
    };
    let rules = r#"
        rule test { meta: severity = 5 description = "test" condition: true }
    "#;
    let pipeline = DetectionPipeline::new(rules, config);
    assert!(pipeline.is_ok());
}

// =============================================================================
// Pipeline from directory tests
// =============================================================================

#[test]
fn from_rules_dir_single_file() {
    let temp_dir = TempDir::new().unwrap();
    let rule = r#"
        rule single {
            meta: severity = 5 description = "single"
            strings: $a = "test"
            condition: $a
        }
    "#;
    fs::write(temp_dir.path().join("single.yar"), rule).unwrap();

    let pipeline = DetectionPipeline::from_rules_dir(temp_dir.path(), PipelineConfig::default());
    assert!(pipeline.is_ok());
}

#[test]
fn from_rules_dir_multiple_files() {
    let temp_dir = TempDir::new().unwrap();

    for i in 1..=5 {
        let rule = format!(
            r#"
            rule rule{} {{
                meta: severity = {} description = "rule{}"
                strings: $a = "test{}"
                condition: $a
            }}
        "#,
            i, i, i, i
        );
        fs::write(temp_dir.path().join(format!("rule{}.yar", i)), rule).unwrap();
    }

    let pipeline = DetectionPipeline::from_rules_dir(temp_dir.path(), PipelineConfig::default());
    assert!(pipeline.is_ok());
}

#[test]
fn from_rules_dir_with_yara_extension() {
    let temp_dir = TempDir::new().unwrap();
    let rule = r#"
        rule yara_ext {
            meta: severity = 5 description = "yara extension"
            condition: true
        }
    "#;
    fs::write(temp_dir.path().join("test.yara"), rule).unwrap();

    let pipeline = DetectionPipeline::from_rules_dir(temp_dir.path(), PipelineConfig::default());
    assert!(pipeline.is_ok());
}

#[test]
fn from_rules_dir_ignores_non_yar_files() {
    let temp_dir = TempDir::new().unwrap();

    let rule = r#"
        rule valid { meta: severity = 5 description = "v" condition: true }
    "#;
    fs::write(temp_dir.path().join("valid.yar"), rule).unwrap();
    fs::write(temp_dir.path().join("readme.txt"), "This is not a rule").unwrap();
    fs::write(temp_dir.path().join("config.json"), "{}").unwrap();

    let pipeline = DetectionPipeline::from_rules_dir(temp_dir.path(), PipelineConfig::default());
    assert!(pipeline.is_ok());
}

#[test]
fn from_rules_dir_empty_returns_error() {
    let temp_dir = TempDir::new().unwrap();
    let pipeline = DetectionPipeline::from_rules_dir(temp_dir.path(), PipelineConfig::default());
    assert!(pipeline.is_err());
}

#[test]
fn from_rules_dir_nonexistent() {
    let pipeline = DetectionPipeline::from_rules_dir(
        std::path::Path::new("/nonexistent/dir"),
        PipelineConfig::default(),
    );
    assert!(pipeline.is_err());
}

// =============================================================================
// Detection result tests
// =============================================================================

#[test]
fn result_is_threat_true() {
    let rules = r#"
        rule threat { meta: severity = 10 description = "threat" strings: $a = "evil" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("evil content").unwrap();
    assert!(result.is_threat());
}

#[test]
fn result_is_threat_false() {
    let rules = r#"
        rule threat { meta: severity = 10 description = "threat" strings: $a = "evil" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("clean content").unwrap();
    assert!(!result.is_threat());
}

#[test]
fn result_threat_level_none() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("no match").unwrap();
    assert_eq!(result.threat_level(), ThreatLevel::None);
}

#[test]
fn result_threat_level_low() {
    let rules = r#"
        rule low { meta: severity = 3 description = "low" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();
    assert_eq!(result.threat_level(), ThreatLevel::Low);
}

#[test]
fn result_threat_level_medium() {
    let rules = r#"
        rule med { meta: severity = 8 description = "med" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();
    assert_eq!(result.threat_level(), ThreatLevel::Medium);
}

#[test]
fn result_threat_level_high() {
    let rules = r#"
        rule high { meta: severity = 10 description = "high" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();
    assert_eq!(result.threat_level(), ThreatLevel::High);
}

#[test]
fn result_recommended_response_allow() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("no match").unwrap();
    assert_eq!(result.recommended_response(), ThreatResponse::Allow);
}

#[test]
fn result_recommended_response_warn() {
    let rules = r#"
        rule low { meta: severity = 5 description = "low" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();
    assert_eq!(result.recommended_response(), ThreatResponse::Warn);
}

#[test]
fn result_recommended_response_prompt() {
    let rules = r#"
        rule med { meta: severity = 7 description = "med" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();
    assert_eq!(result.recommended_response(), ThreatResponse::Prompt);
}

#[test]
fn result_recommended_response_block() {
    let rules = r#"
        rule high { meta: severity = 10 description = "high" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();
    assert_eq!(result.recommended_response(), ThreatResponse::Block);
}

#[test]
fn result_match_count_zero() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("no match").unwrap();
    assert_eq!(result.match_count(), 0);
}

#[test]
fn result_match_count_one() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();
    assert_eq!(result.match_count(), 1);
}

#[test]
fn result_match_count_multiple() {
    let rules = r#"
        rule r1 { meta: severity = 5 description = "r1" strings: $a = "a" condition: $a }
        rule r2 { meta: severity = 6 description = "r2" strings: $b = "b" condition: $b }
        rule r3 { meta: severity = 7 description = "r3" strings: $c = "c" condition: $c }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("abc").unwrap();
    assert_eq!(result.match_count(), 3);
}

// =============================================================================
// Content hash tests
// =============================================================================

#[test]
fn content_hash_is_sha256_length() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" condition: true }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("test content").unwrap();
    assert_eq!(result.content_hash().len(), 64);
}

#[test]
fn content_hash_is_hex() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" condition: true }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("test").unwrap();

    for c in result.content_hash().chars() {
        assert!(c.is_ascii_hexdigit());
    }
}

#[test]
fn content_hash_deterministic() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" condition: true }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();

    let result1 = pipeline.analyze("same content").unwrap();
    let result2 = pipeline.analyze("same content").unwrap();

    assert_eq!(result1.content_hash(), result2.content_hash());
}

#[test]
fn content_hash_different_for_different_content() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" condition: true }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();

    let result1 = pipeline.analyze("content A").unwrap();
    let result2 = pipeline.analyze("content B").unwrap();

    assert_ne!(result1.content_hash(), result2.content_hash());
}

#[test]
fn content_hash_empty_string() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" condition: true }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("").unwrap();

    // SHA-256 of empty string
    assert_eq!(
        result.content_hash(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// =============================================================================
// Report tests
// =============================================================================

#[test]
fn report_no_threats() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("clean").unwrap();

    assert_eq!(result.report(), "No threats detected.");
}

#[test]
fn report_contains_threat_level() {
    let rules = r#"
        rule test { meta: severity = 10 description = "high threat" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();

    assert!(result.report().contains("High"));
}

#[test]
fn report_contains_match_count() {
    let rules = r#"
        rule r1 { meta: severity = 5 description = "r1" strings: $a = "a" condition: $a }
        rule r2 { meta: severity = 6 description = "r2" strings: $b = "b" condition: $b }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("ab").unwrap();

    assert!(result.report().contains("2"));
}

#[test]
fn report_contains_rule_names() {
    let rules = r#"
        rule my_special_rule { meta: severity = 5 description = "special" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();

    assert!(result.report().contains("my_special_rule"));
}

#[test]
fn report_contains_descriptions() {
    let rules = r#"
        rule test { meta: severity = 5 description = "This is a unique description" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();

    assert!(result.report().contains("This is a unique description"));
}

#[test]
fn report_contains_severities() {
    let rules = r#"
        rule test { meta: severity = 8 description = "test" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();
    let result = pipeline.analyze("x").unwrap();

    assert!(result.report().contains("8"));
}

// =============================================================================
// Stress tests
// =============================================================================

#[test]
fn analyze_many_times() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();

    for i in 0..100 {
        let content = format!("test content iteration {}", i);
        let result = pipeline.analyze(&content).unwrap();
        assert!(!result.is_threat());
    }
}

#[test]
fn analyze_large_content() {
    let rules = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "needle" condition: $a }
    "#;
    let pipeline = DetectionPipeline::new(rules, PipelineConfig::default()).unwrap();

    // 5MB content
    let content = "a".repeat(5_000_000);
    let result = pipeline.analyze(&content).unwrap();
    assert!(!result.is_threat());
}

#[test]
fn analyze_with_many_rules() {
    let mut rules = String::new();
    for i in 0..50 {
        // Use 3-digit padding to avoid substring matches (pattern_025 won't match pattern_02)
        rules.push_str(&format!(
            r#"
            rule rule_{:03} {{
                meta:
                    severity = {}
                    description = "rule {:03}"
                strings:
                    $a = "unique_pattern_{:03}"
                condition:
                    $a
            }}
        "#,
            i,
            (i % 10) + 1,
            i,
            i
        ));
    }

    let pipeline = DetectionPipeline::new(&rules, PipelineConfig::default()).unwrap();
    let result = pipeline
        .analyze("unique_pattern_025 unique_pattern_042")
        .unwrap();

    assert!(result.is_threat());
    assert_eq!(result.match_count(), 2);
}
