// src/update/crypto.rs
use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tracing::{debug, warn};

// Embedded public key (replaced during build with actual key)
// For now, use placeholder
const PIPEGUARD_PUBLIC_KEY: &[u8; 32] = &[0u8; 32];

pub struct CryptoVerifier {
    public_key: VerifyingKey,
}

impl std::fmt::Debug for CryptoVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoVerifier")
            .finish_non_exhaustive()
    }
}

impl CryptoVerifier {
    pub fn new() -> Result<Self> {
        let public_key = VerifyingKey::from_bytes(PIPEGUARD_PUBLIC_KEY)
            .context("Invalid embedded public key")?;

        Ok(Self { public_key })
    }

    /// Verify rules signature using embedded public key
    pub fn verify(&self, rules: &[u8], signature: &[u8]) -> Result<()> {
        self.verify_with_key(rules, signature, PIPEGUARD_PUBLIC_KEY)
    }

    /// Verify with custom public key (for testing and enterprise dual-sig)
    pub fn verify_with_key(&self, rules: &[u8], signature: &[u8], public_key: &[u8; 32]) -> Result<()> {
        debug!("Verifying signature");
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .context("Invalid public key format")?;

        let signature = Signature::from_bytes(
            signature.try_into()
                .map_err(|_| anyhow::anyhow!("Signature must be exactly 64 bytes"))?
        );

        match verifying_key.verify(rules, &signature) {
            Ok(()) => {
                debug!("Signature verified successfully");
                Ok(())
            }
            Err(_) => {
                warn!("Signature verification failed");
                Err(anyhow::anyhow!("Signature verification failed: rules may be tampered or invalid"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        // Should succeed even with placeholder key
        let result = CryptoVerifier::new();
        assert!(result.is_ok());
    }
}
