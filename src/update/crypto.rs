// src/update/crypto.rs
use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tracing::{debug, warn};

/// Decode a hex-encoded 32-byte public key at compile time.
/// Returns the fallback (all-zeros) if the env var is missing or malformed.
const fn decode_public_key() -> [u8; 32] {
    match option_env!("PIPEGUARD_PUBLIC_KEY") {
        Some(hex) => {
            let bytes = hex.as_bytes();
            if bytes.len() != 64 {
                return [0u8; 32];
            }
            let mut out = [0u8; 32];
            let mut i = 0;
            while i < 32 {
                let hi = match bytes[i * 2] {
                    b'0'..=b'9' => bytes[i * 2] - b'0',
                    b'a'..=b'f' => bytes[i * 2] - b'a' + 10,
                    b'A'..=b'F' => bytes[i * 2] - b'A' + 10,
                    _ => return [0u8; 32],
                };
                let lo = match bytes[i * 2 + 1] {
                    b'0'..=b'9' => bytes[i * 2 + 1] - b'0',
                    b'a'..=b'f' => bytes[i * 2 + 1] - b'a' + 10,
                    b'A'..=b'F' => bytes[i * 2 + 1] - b'A' + 10,
                    _ => return [0u8; 32],
                };
                out[i] = hi * 16 + lo;
                i += 1;
            }
            out
        }
        None => [0u8; 32],
    }
}

/// Embedded public key. Set `PIPEGUARD_PUBLIC_KEY` env var (64-char hex) at build
/// time to inject a real key. Falls back to all-zeros placeholder for development.
const PIPEGUARD_PUBLIC_KEY: &[u8; 32] = &decode_public_key();

pub struct CryptoVerifier {
    public_key: VerifyingKey,
}

impl std::fmt::Debug for CryptoVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoVerifier").finish_non_exhaustive()
    }
}

impl CryptoVerifier {
    pub fn new() -> Result<Self> {
        // In release builds, refuse to operate with the placeholder key
        #[cfg(not(debug_assertions))]
        if *PIPEGUARD_PUBLIC_KEY == [0u8; 32] {
            anyhow::bail!(
                "Release build contains placeholder public key. \
                 Set PIPEGUARD_PUBLIC_KEY env var at build time."
            );
        }

        if *PIPEGUARD_PUBLIC_KEY == [0u8; 32] {
            warn!("Using placeholder public key — signature verification is NOT secure");
        }

        let public_key = VerifyingKey::from_bytes(PIPEGUARD_PUBLIC_KEY)
            .context("Invalid embedded public key")?;

        Ok(Self { public_key })
    }

    /// Returns true if the verifier was constructed with the all-zeros placeholder key.
    pub fn is_placeholder_key(&self) -> bool {
        self.public_key.to_bytes() == [0u8; 32]
    }

    /// Create a verifier with a custom public key (for testing)
    pub fn from_public_key(bytes: [u8; 32]) -> Result<Self> {
        let public_key = VerifyingKey::from_bytes(&bytes).context("Invalid public key")?;
        Ok(Self { public_key })
    }

    /// Verify rules signature using this verifier's public key
    pub fn verify(&self, rules: &[u8], signature: &[u8]) -> Result<()> {
        debug!("Verifying signature");

        let signature = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("Signature must be exactly 64 bytes"))?,
        );

        match self.public_key.verify(rules, &signature) {
            Ok(()) => {
                debug!("Signature verified successfully");
                Ok(())
            }
            Err(_) => {
                warn!("Signature verification failed");
                Err(anyhow::anyhow!(
                    "Signature verification failed: rules may be tampered or invalid"
                ))
            }
        }
    }

    /// Verify with an explicit public key (for enterprise dual-sig)
    pub fn verify_with_key(
        &self,
        rules: &[u8],
        signature: &[u8],
        public_key: &[u8; 32],
    ) -> Result<()> {
        let verifier = Self::from_public_key(*public_key)?;
        verifier.verify(rules, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        // In debug mode, should succeed even with placeholder key
        let result = CryptoVerifier::new();
        assert!(result.is_ok());
    }

    #[test]
    fn test_placeholder_key_detected() {
        let verifier = CryptoVerifier::new().unwrap();
        // Without PIPEGUARD_PUBLIC_KEY env at build time, key is all-zeros
        assert!(verifier.is_placeholder_key());
    }
}
