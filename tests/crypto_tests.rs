// tests/update/crypto_tests.rs
use pipeguard::update::crypto::CryptoVerifier;

#[test]
fn test_valid_signature_verifies() {
    let verifier = CryptoVerifier::new().unwrap();
    let rules = b"rule test { condition: true }";

    // Use test keypair for this test
    let (public_key, private_key) = generate_test_keypair();
    let signature = sign_test_data(rules, &private_key);

    let result = verifier.verify_with_key(rules, &signature, &public_key);
    assert!(result.is_ok(), "Valid signature should verify");
}

#[test]
fn test_invalid_signature_fails() {
    let verifier = CryptoVerifier::new().unwrap();
    let rules = b"rule test { condition: true }";
    let bad_sig = [0u8; 64];

    let result = verifier.verify(rules, &bad_sig);
    assert!(result.is_err(), "Invalid signature should fail");
}

#[test]
fn test_tampered_rules_fail() {
    let verifier = CryptoVerifier::new().unwrap();
    let rules = b"rule test { condition: true }";
    let tampered = b"rule evil { condition: true }";

    let (public_key, private_key) = generate_test_keypair();
    let signature = sign_test_data(rules, &private_key);

    let result = verifier.verify_with_key(tampered, &signature, &public_key);
    assert!(result.is_err(), "Tampered content should fail verification");
}

// Test helpers
fn generate_test_keypair() -> ([u8; 32], [u8; 32]) {
    use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut secret_bytes = [0u8; SECRET_KEY_LENGTH];
    OsRng.fill_bytes(&mut secret_bytes);

    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key: VerifyingKey = (&signing_key).into();

    (verifying_key.to_bytes(), secret_bytes)
}

fn sign_test_data(data: &[u8], private_key: &[u8; 32]) -> Vec<u8> {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}
