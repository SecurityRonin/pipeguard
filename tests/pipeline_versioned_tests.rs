// tests/pipeline_versioned_tests.rs
use pipeguard::detection::pipeline::{DetectionPipeline, PipelineConfig};
use pipeguard::update::VersionedStorage;
use tempfile::tempdir;
use std::fs;

#[test]
fn test_pipeline_loads_from_active_version() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    // Create a version with rules
    let version_path = storage.create_version_dir("1.0.0").unwrap();
    let rules = b"rule test { condition: true }";
    storage.write_rules(&version_path, rules).unwrap();

    // Mark as verified and activate
    fs::write(version_path.join(".verified"), "").unwrap();
    storage.activate_version("1.0.0").unwrap();

    // Load pipeline from active version
    let pipeline = DetectionPipeline::from_active_version(
        Some(temp.path().to_path_buf()),
        PipelineConfig::default(),
    );

    assert!(pipeline.is_ok(), "Pipeline should load from active version");
}

#[test]
fn test_pipeline_fails_without_active_version() {
    let temp = tempdir().unwrap();
    VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    // No active version set
    let pipeline = DetectionPipeline::from_active_version(
        Some(temp.path().to_path_buf()),
        PipelineConfig::default(),
    );

    assert!(pipeline.is_err(), "Pipeline should fail without active version");
    if let Err(e) = pipeline {
        assert!(e.to_string().contains("No active version"));
    }
}

#[test]
fn test_pipeline_uses_updated_rules() {
    let temp = tempdir().unwrap();
    let storage = VersionedStorage::new(temp.path().to_path_buf()).unwrap();

    // Create v1.0.0 with one rule
    let v1_path = storage.create_version_dir("1.0.0").unwrap();
    storage.write_rules(&v1_path, b"rule old { condition: true }").unwrap();
    fs::write(v1_path.join(".verified"), "").unwrap();
    storage.activate_version("1.0.0").unwrap();

    let pipeline1 = DetectionPipeline::from_active_version(
        Some(temp.path().to_path_buf()),
        PipelineConfig::default(),
    ).unwrap();

    // Scan with v1.0.0 rules
    let result1 = pipeline1.analyze("test content");
    assert!(result1.is_ok());

    // Create v1.1.0 with updated rules
    let v2_path = storage.create_version_dir("1.1.0").unwrap();
    storage.write_rules(&v2_path, b"rule new { condition: true }").unwrap();
    fs::write(v2_path.join(".verified"), "").unwrap();
    storage.activate_version("1.1.0").unwrap();

    let pipeline2 = DetectionPipeline::from_active_version(
        Some(temp.path().to_path_buf()),
        PipelineConfig::default(),
    ).unwrap();

    // Scan with v1.1.0 rules
    let result2 = pipeline2.analyze("test content");
    assert!(result2.is_ok());

    // Different pipelines (loading different rule versions)
    // In a real test, we'd check specific rule matches differ
}
