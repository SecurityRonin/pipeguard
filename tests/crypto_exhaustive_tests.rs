// Exhaustive tests for CryptoVerifier
// Covers: key construction, signature verification, edge cases, error paths

use anyhow::Result;
use ed25519_dalek::Signer;
use pipeguard::update::CryptoVerifier;

// ─── Key construction ───────────────────────────────────────────

#[test]
fn from_public_key_valid_keypair() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"test content";
    let sig = keypair.sign(content);
    assert!(verifier.verify(content, &sig.to_bytes()).is_ok());
    Ok(())
}

#[test]
fn new_uses_embedded_key() {
    // The embedded key is a zero placeholder, but new() should succeed
    let result = CryptoVerifier::new();
    assert!(result.is_ok());
}

#[test]
fn from_public_key_all_zeros_succeeds() {
    // All zeros is technically a valid ed25519 point (the identity)
    let result = CryptoVerifier::from_public_key([0u8; 32]);
    assert!(result.is_ok());
}

// ─── Signature verification ────────────────────────────────────

#[test]
fn verify_correct_signature() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"rule legitimate { condition: true }";
    let sig = keypair.sign(content);

    assert!(verifier.verify(content, &sig.to_bytes()).is_ok());
    Ok(())
}

#[test]
fn verify_wrong_content_fails() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"original content";
    let sig = keypair.sign(content);

    assert!(verifier
        .verify(b"modified content", &sig.to_bytes())
        .is_err());
    Ok(())
}

#[test]
fn verify_wrong_key_fails() -> Result<()> {
    let keypair1 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let keypair2 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    let verifier = CryptoVerifier::from_public_key(keypair2.verifying_key().to_bytes())?;

    let content = b"content";
    let sig = keypair1.sign(content); // Signed with keypair1

    assert!(verifier.verify(content, &sig.to_bytes()).is_err()); // Verified with keypair2
    Ok(())
}

// ─── Signature size validation ──────────────────────────────────

#[test]
fn verify_empty_signature_fails() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let result = verifier.verify(b"content", &[]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("64 bytes"));
    Ok(())
}

#[test]
fn verify_short_signature_fails() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    assert!(verifier.verify(b"content", &[0u8; 32]).is_err());
    assert!(verifier.verify(b"content", &[0u8; 63]).is_err());
    Ok(())
}

#[test]
fn verify_long_signature_fails() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    assert!(verifier.verify(b"content", &[0u8; 65]).is_err());
    assert!(verifier.verify(b"content", &[0u8; 128]).is_err());
    Ok(())
}

#[test]
fn verify_garbage_64_byte_signature_fails() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    assert!(verifier.verify(b"content", &[0xFF; 64]).is_err());
    Ok(())
}

// ─── Content edge cases ─────────────────────────────────────────

#[test]
fn verify_empty_content() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"";
    let sig = keypair.sign(content);
    assert!(verifier.verify(content, &sig.to_bytes()).is_ok());
    Ok(())
}

#[test]
fn verify_large_content() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = vec![b'x'; 1024 * 1024]; // 1MB
    let sig = keypair.sign(&content);
    assert!(verifier.verify(&content, &sig.to_bytes()).is_ok());
    Ok(())
}

#[test]
fn verify_single_bit_flip_detected() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"rule safe { condition: true }";
    let sig = keypair.sign(content);

    let mut tampered = content.to_vec();
    tampered[0] ^= 0x01;
    assert!(verifier.verify(&tampered, &sig.to_bytes()).is_err());
    Ok(())
}

#[test]
fn verify_appended_content_detected() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"rule safe { condition: true }";
    let sig = keypair.sign(content);

    let mut extended = content.to_vec();
    extended.extend_from_slice(b"\nrule backdoor { condition: true }");
    assert!(verifier.verify(&extended, &sig.to_bytes()).is_err());
    Ok(())
}

#[test]
fn verify_truncated_content_detected() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"rule safe { condition: true }";
    let sig = keypair.sign(content);

    assert!(verifier.verify(&content[..10], &sig.to_bytes()).is_err());
    Ok(())
}

// ─── verify_with_key ────────────────────────────────────────────

#[test]
fn verify_with_key_correct() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::new()?; // Uses embedded key

    let content = b"content";
    let sig = keypair.sign(content);

    // Verify with explicit key (should succeed since we pass the correct key)
    assert!(verifier
        .verify_with_key(
            content,
            &sig.to_bytes(),
            &keypair.verifying_key().to_bytes()
        )
        .is_ok());
    Ok(())
}

#[test]
fn verify_with_key_wrong_key() -> Result<()> {
    let keypair1 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let keypair2 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::new()?;

    let content = b"content";
    let sig = keypair1.sign(content);

    assert!(verifier
        .verify_with_key(
            content,
            &sig.to_bytes(),
            &keypair2.verifying_key().to_bytes()
        )
        .is_err());
    Ok(())
}

// ─── Replay attack ──────────────────────────────────────────────

#[test]
fn signature_not_transferable_between_contents() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content_a = b"version 1.0";
    let content_b = b"version 2.0";
    let sig_a = keypair.sign(content_a);
    let sig_b = keypair.sign(content_b);

    // Cross-verification must fail
    assert!(verifier.verify(content_a, &sig_b.to_bytes()).is_err());
    assert!(verifier.verify(content_b, &sig_a.to_bytes()).is_err());

    // Self-verification must succeed
    assert!(verifier.verify(content_a, &sig_a.to_bytes()).is_ok());
    assert!(verifier.verify(content_b, &sig_b.to_bytes()).is_ok());
    Ok(())
}

// ─── Deterministic signatures ───────────────────────────────────

#[test]
fn same_content_same_key_same_signature() -> Result<()> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let verifier = CryptoVerifier::from_public_key(keypair.verifying_key().to_bytes())?;

    let content = b"deterministic content";
    let sig1 = keypair.sign(content);
    let sig2 = keypair.sign(content);

    // Ed25519 is deterministic
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    assert!(verifier.verify(content, &sig1.to_bytes()).is_ok());
    Ok(())
}
