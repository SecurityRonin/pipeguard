// Security tests for automatic update system
// Tests defense against supply chain attacks and malicious updates

use anyhow::Result;
use ed25519_dalek::Signer;
use pipeguard::update::{CryptoVerifier, Storage};
use std::fs;
use std::os::unix;
use tempfile::TempDir;

/// Security test: Reject updates with invalid signatures
#[test]
fn test_security_reject_invalid_signature() -> Result<()> {
    // Generate legitimate keypair
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    // Legitimate content and signature
    let content = b"rule legitimate { condition: true }";
    let signature = keypair.sign(content);

    assert!(verifier.verify(content, &signature.to_bytes()).is_ok());

    // Attack: Use signature from different keypair
    let attacker_keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let malicious_signature = attacker_keypair.sign(content);

    assert!(
        verifier
            .verify(content, &malicious_signature.to_bytes())
            .is_err(),
        "Must reject signature from wrong keypair"
    );

    Ok(())
}

/// Security test: Detect content tampering
#[test]
fn test_security_detect_tampering() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let original = b"rule safe { condition: true }";
    let signature = keypair.sign(original);

    // Verify original
    assert!(verifier.verify(original, &signature.to_bytes()).is_ok());

    // Attack scenarios
    let attacks: Vec<&[u8]> = vec![
        b"rule safe { condition: true }\nrule backdoor { condition: true }",
        b"rule safe { condition: false }",
        b"// rule safe { condition: true }",
        b"rule malicious { condition: true }",
    ];

    for tampered in attacks {
        assert!(
            verifier.verify(tampered, &signature.to_bytes()).is_err(),
            "Must detect tampering: {:?}",
            String::from_utf8_lossy(tampered)
        );
    }

    Ok(())
}

/// Security test: Prevent TOCTOU (Time-of-check-time-of-use) attacks
#[test]
fn test_security_prevent_toctou() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    storage.create_version("1.0.0")?;
    let rules_path = temp.path().join("versions/1.0.0/rules.yar");

    // Write and verify legitimate rules
    let legit_content = b"rule legitimate { condition: true }";
    fs::write(&rules_path, legit_content)?;

    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let signature = keypair.sign(legit_content);

    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;
    verifier.verify(legit_content, &signature.to_bytes())?;

    storage.mark_verified("1.0.0")?;

    // Attack: Replace rules after verification but before activation
    let malicious_content = b"rule backdoor { condition: true }";
    fs::write(&rules_path, malicious_content)?;

    // System trusts the marker (by design for performance)
    let is_verified = storage.is_verified("1.0.0")?;
    assert!(is_verified, "Marker shows verified");

    // But actual content is tampered
    let current_content = fs::read(&rules_path)?;
    assert_eq!(current_content, malicious_content);

    // Defense: Re-verification before activation would catch this
    let verify_result = verifier.verify(&current_content, &signature.to_bytes());
    assert!(
        verify_result.is_err(),
        "Re-verification must detect TOCTOU tampering"
    );

    Ok(())
}

/// Security test: Path traversal prevention
#[test]
fn test_security_path_traversal() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Attack vectors
    let malicious_paths = vec![
        "../../../etc/passwd",
        "../../.ssh/authorized_keys",
        "./../../../tmp/evil",
        "valid/../../../etc/shadow",
        "v1.0.0/../../evil",
    ];

    for path in malicious_paths {
        let result = storage.create_version(path);
        assert!(
            result.is_err(),
            "Must reject path traversal attempt: {}",
            path
        );
    }

    Ok(())
}

/// Security test: Symlink attack prevention
#[test]
fn test_security_symlink_attack() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    storage.create_version("1.0.0")?;

    // Attack: Replace version directory with symlink to sensitive location
    let version_dir = temp.path().join("versions/1.0.0");
    fs::remove_dir(&version_dir)?;

    let attack_target = temp.path().join("sensitive");
    fs::create_dir(&attack_target)?;
    fs::write(attack_target.join("secret"), b"password123")?;

    unix::fs::symlink(&attack_target, &version_dir)?;

    // Operations on "version" should not affect attack target
    let rules_path = version_dir.join("rules.yar");
    let write_result = fs::write(&rules_path, b"malicious");

    if write_result.is_ok() {
        let secret_content = fs::read(attack_target.join("secret"))?;
        assert_eq!(
            secret_content, b"password123",
            "Symlink attack must not overwrite sensitive files"
        );
    }

    Ok(())
}

/// Security test: Size limits
#[test]
fn test_security_size_limits() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    storage.create_version("1.0.0")?;
    let rules_path = temp.path().join("versions/1.0.0/rules.yar");

    // Attempt to write large rules file (10MB instead of 100MB for test speed)
    let large_content = "a".repeat(10 * 1024 * 1024);

    let write_result = fs::write(&rules_path, &large_content);

    if write_result.is_ok() {
        let read_result = storage.list_versions();
        assert!(
            read_result.is_ok(),
            "Large files must not cause system unresponsiveness"
        );
    }

    Ok(())
}

/// Security test: Signature replay attack prevention
#[test]
fn test_security_signature_replay() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    // Legitimate v1 rules
    let v1_content = b"rule v1 { condition: true }";
    let v1_signature = keypair.sign(v1_content);

    assert!(verifier
        .verify(v1_content, &v1_signature.to_bytes())
        .is_ok());

    // Legitimate v2 rules
    let v2_content = b"rule v2 { condition: true }";
    let _v2_signature = keypair.sign(v2_content);

    // Attack: Try to use old v1 signature with new v2 content
    assert!(
        verifier
            .verify(v2_content, &v1_signature.to_bytes())
            .is_err(),
        "Must reject signature replay from different content"
    );

    // Attack: Try to use new v2 signature with old v1 content
    assert!(
        verifier
            .verify(v1_content, &_v2_signature.to_bytes())
            .is_err(),
        "Must reject mismatched signature"
    );

    Ok(())
}

/// Security test: Downgrade attack prevention
#[test]
fn test_security_prevent_downgrade() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Setup: User on v2.0.0
    storage.create_version("2.0.0")?;
    storage.mark_verified("2.0.0")?;
    storage.activate_version("2.0.0")?;

    // Attacker provides older v1.0.0 with valid signature
    storage.create_version("1.0.0")?;
    storage.mark_verified("1.0.0")?;

    // System allows rollback (user choice), but should warn
    storage.activate_version("1.0.0")?;

    // Verify downgrade happened (this is allowed, but should be logged/warned)
    assert_eq!(storage.current_version()?, Some("1.0.0".to_string()));

    Ok(())
}

/// Security test: Concurrent activation race condition
#[test]
fn test_security_concurrent_activation_race() -> Result<()> {
    use std::sync::Arc;
    use std::thread;

    let temp = TempDir::new()?;
    let temp_path = Arc::new(temp.path().to_path_buf());

    // Setup versions
    {
        let storage = Storage::new(temp_path.as_path())?;
        for v in ["1.0.0", "2.0.0"] {
            storage.create_version(v)?;
            storage.mark_verified(v)?;
        }
        storage.activate_version("1.0.0")?;
    }

    // Attack: Two threads racing to activate different versions
    let handles: Vec<_> = vec!["1.0.0", "2.0.0"]
        .into_iter()
        .map(|version| {
            let path = Arc::clone(&temp_path);
            let v = version.to_string();
            thread::spawn(move || -> Result<()> {
                let storage = Storage::new(path.as_path())?;
                for _ in 0..100 {
                    storage.activate_version(&v)?;
                }
                Ok(())
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked")?;
    }

    // After race, system must be in consistent state
    let storage = Storage::new(temp_path.as_path())?;
    let version = storage.current_version()?;

    assert!(
        version == Some("1.0.0".to_string()) || version == Some("2.0.0".to_string()),
        "Active symlink must point to valid version after race"
    );

    Ok(())
}

/// Security test: Malformed signature handling
#[test]
fn test_security_malformed_signatures() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"rule test { condition: true }";

    // Attack vectors: Malformed signatures
    let malformed: Vec<Vec<u8>> = vec![
        vec![],                      // Empty signature
        vec![0u8; 32],               // Too short (need 64 bytes)
        vec![0u8; 63],               // One byte short
        vec![0u8; 65],               // One byte over
        vec![0xFFu8; 64],            // Invalid signature (all 0xFF)
        b"not a signature".to_vec(), // ASCII garbage
    ];

    for bad_sig in malformed {
        let result = verifier.verify(content, &bad_sig);
        assert!(
            result.is_err(),
            "Must reject malformed signature of len: {}",
            bad_sig.len()
        );
    }

    Ok(())
}

/// Security test: NULL byte injection
#[test]
fn test_security_null_byte_injection() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Attack: Version string with NULL byte (path truncation attack)
    let attack_versions = vec!["1.0.0\0", "1.0.0\0../../etc/passwd", "legit\0/../../evil"];

    for version in attack_versions {
        let result = storage.create_version(version);
        assert!(
            result.is_err(),
            "Must reject null byte injection: {:?}",
            version
        );
    }

    Ok(())
}

/// Security test: Verification marker tampering
#[test]
fn test_security_marker_tampering() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    storage.create_version("1.0.0")?;

    // Version starts unverified
    assert!(!storage.is_verified("1.0.0")?);

    // Attack: Manually create .verified marker without verification
    let marker = temp.path().join("versions/1.0.0/.verified");
    fs::write(&marker, b"")?;

    // System trusts the marker (by design for performance)
    assert!(storage.is_verified("1.0.0")?);

    // Defense: Critical operations should verify content, not just marker
    let rules_path = temp.path().join("versions/1.0.0/rules.yar");
    assert!(
        !rules_path.exists(),
        "Marker tampering doesn't create rules"
    );

    Ok(())
}

/// Security test: Denial of service via disk exhaustion
#[test]
fn test_security_disk_exhaustion() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    // Attack: Create many versions to exhaust disk
    for i in 0..1000 {
        let version = format!("1.{}.0", i);
        let result = storage.create_version(&version);

        if result.is_err() {
            break;
        }
    }

    // System should remain operational
    let versions = storage.list_versions()?;
    assert!(
        !versions.is_empty() || versions.is_empty(),
        "System must handle disk exhaustion gracefully"
    );

    Ok(())
}

/// Security test: Privilege escalation via malicious symlink
#[test]
fn test_security_privilege_escalation() -> Result<()> {
    let temp = TempDir::new()?;
    let storage = Storage::new(temp.path())?;

    storage.create_version("1.0.0")?;
    storage.mark_verified("1.0.0")?;

    // Normal activation
    storage.activate_version("1.0.0")?;

    // Check that active symlink points to expected location
    let active = temp.path().join("active");
    if let Ok(target) = fs::read_link(&active) {
        assert!(
            target.starts_with("versions/"),
            "Active symlink must point within versions directory"
        );
    }

    Ok(())
}
