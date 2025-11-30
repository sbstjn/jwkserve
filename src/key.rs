use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::KeySignAlgorithm;

#[derive(Error, Debug)]
pub enum RsaKeyError {
    #[error("invalid RSA key size: {0} (must be 2048, 3072, or 4096)")]
    InvalidKeySize(usize),

    #[error("failed to generate RSA key")]
    FailedToGenerate,

    #[error("failed to encode RSA key to PEM format")]
    FailedToEncode,

    #[error("failed to decode RSA key from PEM format")]
    FailedToDecode,

    #[error("failed to read key file: {path}")]
    FailedToReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("key file too large: {size} bytes (maximum: {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },

    #[error("failed to sign JWT: {0}")]
    FailedToSign(String),
}

/// RSA private key for JWT signing operations
#[derive(Clone, Debug)]
pub struct RsaPrivateKey {
    inner: rsa::RsaPrivateKey,
    /// Cached PEM encoding for signing operations
    pem_cache: String,
}

impl RsaPrivateKey {
    /// Generate a new RSA private key with the specified bit size
    ///
    /// # Arguments
    /// * `bits` - Key size in bits (must be 2048, 3072, or 4096)
    pub fn generate(bits: usize) -> Result<Self, RsaKeyError> {
        if bits != 2048 && bits != 3072 && bits != 4096 {
            return Err(RsaKeyError::InvalidKeySize(bits));
        }

        let mut rng = rand::thread_rng();
        let inner =
            rsa::RsaPrivateKey::new(&mut rng, bits).map_err(|_| RsaKeyError::FailedToGenerate)?;

        let pem_cache = inner
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| RsaKeyError::FailedToEncode)?
            .to_string();

        Ok(Self { inner, pem_cache })
    }

    /// Load RSA private key from PEM-encoded string
    ///
    /// Validates PEM string length to prevent resource exhaustion (max 64KB)
    pub fn from_pem(pem: &str) -> Result<Self, RsaKeyError> {
        const MAX_PEM_SIZE: usize = 64 * 1024; // 64KB

        if pem.len() > MAX_PEM_SIZE {
            return Err(RsaKeyError::FileTooLarge {
                size: pem.len() as u64,
                max: MAX_PEM_SIZE as u64,
            });
        }

        let inner =
            rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| RsaKeyError::FailedToDecode)?;

        Ok(Self {
            inner,
            pem_cache: pem.to_string(),
        })
    }

    /// Load RSA private key from PEM file
    ///
    /// Validates file size to prevent resource exhaustion (max 64KB for PEM keys)
    pub fn from_pem_file(path: &Path) -> Result<Self, RsaKeyError> {
        const MAX_KEY_FILE_SIZE: u64 = 64 * 1024; // 64KB

        let metadata = std::fs::metadata(path).map_err(|e| RsaKeyError::FailedToReadFile {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        if metadata.len() > MAX_KEY_FILE_SIZE {
            return Err(RsaKeyError::FileTooLarge {
                size: metadata.len(),
                max: MAX_KEY_FILE_SIZE,
            });
        }

        let pem = std::fs::read_to_string(path).map_err(|e| RsaKeyError::FailedToReadFile {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        Self::from_pem(&pem)
    }

    /// Export RSA private key to PEM format (PKCS#8)
    pub fn to_pem(&self) -> Result<String, RsaKeyError> {
        Ok(self.pem_cache.clone())
    }

    /// Export RSA public key to PEM format (PKCS#8)
    pub fn to_public_pem(&self) -> Result<String, RsaKeyError> {
        let public_key = RsaPublicKey::from(&self.inner);

        public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| RsaKeyError::FailedToEncode)
    }

    /// Get the key size in bits
    pub fn size_bits(&self) -> usize {
        self.inner.n().bits()
    }

    /// Sign arbitrary JWT claims with the specified algorithm
    ///
    /// # Arguments
    /// * `claims` - JSON value containing the JWT claims
    /// * `algorithm` - The signing algorithm to use
    ///
    /// # Returns
    /// The signed JWT token as a string
    pub fn sign_jwt(
        &self,
        claims: &Value,
        algorithm: &KeySignAlgorithm,
    ) -> Result<String, RsaKeyError> {
        let alg = match algorithm {
            KeySignAlgorithm::RS256 => Algorithm::RS256,
            KeySignAlgorithm::RS384 => Algorithm::RS384,
            KeySignAlgorithm::RS512 => Algorithm::RS512,
        };

        // Use cached PEM encoding for efficiency
        let encoding_key = EncodingKey::from_rsa_pem(self.pem_cache.as_bytes())
            .map_err(|e| RsaKeyError::FailedToSign(e.to_string()))?;

        // Calculate kid to match JWK - must be identical to to_jwk() output
        let kid = self.calculate_kid(algorithm);

        let mut header = Header::new(alg);
        header.kid = Some(kid);

        encode(&header, claims, &encoding_key).map_err(|e| RsaKeyError::FailedToSign(e.to_string()))
    }

    /// Calculate Key ID (kid) for a given algorithm
    ///
    /// The kid is calculated as SHA-256 thumbprint per RFC 7638,
    /// suffixed with the algorithm to support multiple algorithms per key.
    fn calculate_kid(&self, alg: &KeySignAlgorithm) -> String {
        let n = self.inner.n().to_bytes_be();
        let e = self.inner.e().to_bytes_be();

        let n_b64 = URL_SAFE_NO_PAD.encode(&n);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e);

        // RFC 7638: SHA-256 of lexicographically ordered required members
        let thumbprint_input = format!(r#"{{"e":"{e_b64}","kty":"RSA","n":"{n_b64}"}}"#);
        let mut hasher = Sha256::new();
        hasher.update(thumbprint_input.as_bytes());
        let thumbprint = hasher.finalize();
        let kid_base = URL_SAFE_NO_PAD.encode(thumbprint);

        format!("{}-{}", kid_base, alg.as_str())
    }

    /// Export RSA public key as JSON Web Key (JWK)
    ///
    /// Returns a JWK representation according to RFC 7517 and RFC 7518.
    /// The Key ID (kid) is calculated as a SHA-256 thumbprint per RFC 7638.
    ///
    /// # Arguments
    /// * `alg` - The signing algorithm
    pub fn to_jwk(&self, alg: &KeySignAlgorithm) -> Value {
        let n = self.inner.n().to_bytes_be();
        let e = self.inner.e().to_bytes_be();

        let n_b64 = URL_SAFE_NO_PAD.encode(&n);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e);

        let kid = self.calculate_kid(alg);

        json!({
            "kty": "RSA",
            "use": "sig",
            "kid": kid,
            "alg": alg.as_str(),
            "n": n_b64,
            "e": e_b64
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_pem_validates_size() {
        // Create a string larger than 64KB
        let oversized_pem = "x".repeat(65 * 1024);

        let result = RsaPrivateKey::from_pem(&oversized_pem);
        assert!(result.is_err());

        match result.unwrap_err() {
            RsaKeyError::FileTooLarge { size, max } => {
                assert_eq!(size, 65 * 1024);
                assert_eq!(max, 64 * 1024);
            }
            _ => panic!("Expected FileTooLarge error"),
        }
    }

    #[test]
    fn test_pem_cache_used_for_signing() {
        // Generate a key
        let key = RsaPrivateKey::generate(2048).expect("Failed to generate key");

        // Verify PEM cache is populated
        assert!(!key.pem_cache.is_empty());

        // Sign a JWT and ensure it works (uses cached PEM)
        let claims = serde_json::json!({"sub": "test", "exp": 9999999999_i64});
        let result = key.sign_jwt(&claims, &KeySignAlgorithm::RS256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_to_pem_returns_cached_value() {
        let key = RsaPrivateKey::generate(2048).expect("Failed to generate key");

        let pem1 = key.to_pem().expect("Failed to get PEM");
        let pem2 = key.to_pem().expect("Failed to get PEM");

        // Should return identical cached value
        assert_eq!(pem1, pem2);
        assert_eq!(pem1, key.pem_cache);
    }

    #[test]
    fn test_invalid_key_size() {
        let result = RsaPrivateKey::generate(1024);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RsaKeyError::InvalidKeySize(1024)
        ));

        let result = RsaPrivateKey::generate(8192);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RsaKeyError::InvalidKeySize(8192)
        ));
    }

    #[test]
    fn test_from_pem_invalid_format() {
        let result = RsaPrivateKey::from_pem("not a valid pem");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RsaKeyError::FailedToDecode));
    }

    #[test]
    fn test_to_public_pem() {
        let key = RsaPrivateKey::generate(2048).expect("Failed to generate key");
        let public_pem = key.to_public_pem().expect("Failed to export public key");

        // Should contain PUBLIC KEY header
        assert!(public_pem.contains("BEGIN PUBLIC KEY"));
        assert!(public_pem.contains("END PUBLIC KEY"));
        // Should NOT contain PRIVATE KEY
        assert!(!public_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_key_size_bits() {
        // Test with 2048-bit key (faster than testing all sizes)
        let key = RsaPrivateKey::generate(2048).expect("Failed to generate key");
        assert_eq!(key.size_bits(), 2048);
    }
}
