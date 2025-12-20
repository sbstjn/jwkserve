use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p521::ecdsa::{signature::Signer, Signature as P521Signature, SigningKey as P521SigningKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use crate::KeySignAlgorithm;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("invalid RSA key size: {0} (must be 2048, 3072, or 4096)")]
    InvalidRsaKeySize(usize),

    #[error("invalid ECDSA curve: {0}")]
    InvalidEcdsaCurve(String),

    #[error("failed to generate RSA key")]
    FailedToGenerateRsa,

    #[error("failed to generate ECDSA key")]
    FailedToGenerateEcdsa,

    #[error("failed to encode RSA key to PEM format")]
    FailedToEncodeRsa,

    #[error("failed to encode ECDSA key to PEM format")]
    FailedToEncodeEcdsa,

    #[error("failed to decode RSA key from PEM format")]
    FailedToDecodeRsa,

    #[error("failed to decode ECDSA key from PEM format")]
    FailedToDecodeEcdsa,

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
    pub fn generate(bits: usize) -> Result<Self, KeyError> {
        if bits != 2048 && bits != 3072 && bits != 4096 {
            return Err(KeyError::InvalidRsaKeySize(bits));
        }

        let mut rng = rand::thread_rng();
        let inner =
            rsa::RsaPrivateKey::new(&mut rng, bits).map_err(|_| KeyError::FailedToGenerateRsa)?;

        let pem_cache = inner
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| KeyError::FailedToEncodeRsa)?
            .to_string();

        Ok(Self { inner, pem_cache })
    }

    /// Load RSA private key from PEM-encoded string
    ///
    /// Validates PEM string length to prevent resource exhaustion (max 64KB)
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        const MAX_PEM_SIZE: usize = 64 * 1024; // 64KB

        if pem.len() > MAX_PEM_SIZE {
            return Err(KeyError::FileTooLarge {
                size: pem.len() as u64,
                max: MAX_PEM_SIZE as u64,
            });
        }

        let inner =
            rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| KeyError::FailedToDecodeRsa)?;

        Ok(Self {
            inner,
            pem_cache: pem.to_string(),
        })
    }

    /// Load RSA private key from PEM file
    ///
    /// Validates file size to prevent resource exhaustion (max 64KB for PEM keys)
    pub fn from_pem_file(path: &Path) -> Result<Self, KeyError> {
        const MAX_KEY_FILE_SIZE: u64 = 64 * 1024; // 64KB

        let metadata = std::fs::metadata(path).map_err(|e| KeyError::FailedToReadFile {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        if metadata.len() > MAX_KEY_FILE_SIZE {
            return Err(KeyError::FileTooLarge {
                size: metadata.len(),
                max: MAX_KEY_FILE_SIZE,
            });
        }

        let pem = std::fs::read_to_string(path).map_err(|e| KeyError::FailedToReadFile {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        Self::from_pem(&pem)
    }

    /// Export RSA private key to PEM format (PKCS#8)
    pub fn to_pem(&self) -> Result<String, KeyError> {
        Ok(self.pem_cache.clone())
    }

    /// Export RSA public key to PEM format (PKCS#8)
    pub fn to_public_pem(&self) -> Result<String, KeyError> {
        let public_key = RsaPublicKey::from(&self.inner);

        public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| KeyError::FailedToEncodeRsa)
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
    ) -> Result<String, KeyError> {
        let alg = match algorithm {
            KeySignAlgorithm::RS256 => Algorithm::RS256,
            KeySignAlgorithm::RS384 => Algorithm::RS384,
            KeySignAlgorithm::RS512 => Algorithm::RS512,
            _ => {
                return Err(KeyError::FailedToSign(
                    "unsupported algorithm for RSA key".to_string(),
                ))
            }
        };

        // Use cached PEM encoding for efficiency
        let encoding_key = EncodingKey::from_rsa_pem(self.pem_cache.as_bytes())
            .map_err(|e| KeyError::FailedToSign(e.to_string()))?;

        // Calculate kid to match JWK - must be identical to to_jwk() output
        let kid = self.calculate_kid(algorithm);

        let mut header = Header::new(alg);
        header.kid = Some(kid);

        encode(&header, claims, &encoding_key).map_err(|e| KeyError::FailedToSign(e.to_string()))
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

/// Supported ECDSA curves
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcdsaCurve {
    P256,
    P384,
    P521,
}

impl EcdsaCurve {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }
}

/// ECDSA private key wrapper supporting multiple curves
#[derive(Clone, Debug)]
enum EcdsaKey {
    P256(P256SigningKey),
    P384(P384SigningKey),
    P521(P521SigningKey),
}

/// ECDSA private key for JWT signing operations
#[derive(Clone, Debug)]
pub struct EcdsaPrivateKey {
    inner: EcdsaKey,
    curve: EcdsaCurve,
    /// Cached PEM encoding for signing operations
    pem_cache: String,
}

impl EcdsaPrivateKey {
    /// Generate a new ECDSA private key with the specified curve
    ///
    /// # Arguments
    /// * `curve` - The elliptic curve to use (P-256, P-384, or P-521)
    pub fn generate(curve: EcdsaCurve) -> Result<Self, KeyError> {
        use elliptic_curve::pkcs8::EncodePrivateKey as EcEncodePrivateKey;

        let (inner, pem_cache) = match &curve {
            EcdsaCurve::P256 => {
                let key = P256SigningKey::generate();
                let pem = key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|_| KeyError::FailedToEncodeEcdsa)?
                    .to_string();
                (EcdsaKey::P256(key), pem)
            }
            EcdsaCurve::P384 => {
                let key = P384SigningKey::generate();
                let pem = key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|_| KeyError::FailedToEncodeEcdsa)?
                    .to_string();
                (EcdsaKey::P384(key), pem)
            }
            EcdsaCurve::P521 => {
                let key = P521SigningKey::generate();
                let pem = key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|_| KeyError::FailedToEncodeEcdsa)?
                    .to_string();
                (EcdsaKey::P521(key), pem)
            }
        };

        Ok(Self {
            inner,
            curve,
            pem_cache,
        })
    }

    /// Load ECDSA private key from PEM-encoded string
    ///
    /// Validates PEM string length to prevent resource exhaustion (max 64KB)
    /// Automatically detects the curve from the key
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        use elliptic_curve::pkcs8::DecodePrivateKey as EcDecodePrivateKey;

        const MAX_PEM_SIZE: usize = 64 * 1024; // 64KB

        if pem.len() > MAX_PEM_SIZE {
            return Err(KeyError::FileTooLarge {
                size: pem.len() as u64,
                max: MAX_PEM_SIZE as u64,
            });
        }

        // Try each curve type
        if let Ok(key) = P256SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self {
                inner: EcdsaKey::P256(key),
                curve: EcdsaCurve::P256,
                pem_cache: pem.to_string(),
            });
        }

        if let Ok(key) = P384SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self {
                inner: EcdsaKey::P384(key),
                curve: EcdsaCurve::P384,
                pem_cache: pem.to_string(),
            });
        }

        if let Ok(key) = P521SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self {
                inner: EcdsaKey::P521(key),
                curve: EcdsaCurve::P521,
                pem_cache: pem.to_string(),
            });
        }

        Err(KeyError::FailedToDecodeEcdsa)
    }

    /// Load ECDSA private key from PEM file
    ///
    /// Validates file size to prevent resource exhaustion (max 64KB for PEM keys)
    pub fn from_pem_file(path: &Path) -> Result<Self, KeyError> {
        const MAX_KEY_FILE_SIZE: u64 = 64 * 1024; // 64KB

        let metadata = std::fs::metadata(path).map_err(|e| KeyError::FailedToReadFile {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        if metadata.len() > MAX_KEY_FILE_SIZE {
            return Err(KeyError::FileTooLarge {
                size: metadata.len(),
                max: MAX_KEY_FILE_SIZE,
            });
        }

        let pem = std::fs::read_to_string(path).map_err(|e| KeyError::FailedToReadFile {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        Self::from_pem(&pem)
    }

    /// Export ECDSA private key to PEM format (PKCS#8)
    pub fn to_pem(&self) -> Result<String, KeyError> {
        Ok(self.pem_cache.clone())
    }

    /// Export ECDSA public key to PEM format (PKCS#8)
    pub fn to_public_pem(&self) -> Result<String, KeyError> {
        use elliptic_curve::pkcs8::EncodePublicKey as EcEncodePublicKey;

        let pem = match &self.inner {
            EcdsaKey::P256(key) => key
                .verifying_key()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF),
            EcdsaKey::P384(key) => key
                .verifying_key()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF),
            EcdsaKey::P521(key) => key
                .verifying_key()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF),
        };

        pem.map_err(|_| KeyError::FailedToEncodeEcdsa)
    }

    /// Get the curve name
    pub fn curve(&self) -> &EcdsaCurve {
        &self.curve
    }

    /// Sign arbitrary JWT claims with the specified algorithm
    ///
    /// # Arguments
    /// * `claims` - JSON value containing the JWT claims
    /// * `algorithm` - The signing algorithm to use (must match the curve)
    ///
    /// # Returns
    /// The signed JWT token as a string
    pub fn sign_jwt(
        &self,
        claims: &Value,
        algorithm: &KeySignAlgorithm,
    ) -> Result<String, KeyError> {
        // Validate algorithm matches curve
        match (&self.curve, algorithm) {
            (EcdsaCurve::P256, KeySignAlgorithm::ES256)
            | (EcdsaCurve::P384, KeySignAlgorithm::ES384)
            | (EcdsaCurve::P521, KeySignAlgorithm::ES512) => {}
            _ => {
                return Err(KeyError::FailedToSign(format!(
                    "algorithm {:?} does not match curve {}",
                    algorithm,
                    self.curve.as_str()
                )))
            }
        }

        // ES512 requires manual implementation as jsonwebtoken doesn't support it
        if matches!(algorithm, KeySignAlgorithm::ES512) {
            return self.sign_jwt_es512(claims);
        }

        let alg = match algorithm {
            KeySignAlgorithm::ES256 => Algorithm::ES256,
            KeySignAlgorithm::ES384 => Algorithm::ES384,
            _ => {
                return Err(KeyError::FailedToSign(
                    "unsupported algorithm for ECDSA key".to_string(),
                ))
            }
        };

        // Use cached PEM encoding for efficiency
        let encoding_key = EncodingKey::from_ec_pem(self.pem_cache.as_bytes())
            .map_err(|e| KeyError::FailedToSign(e.to_string()))?;

        // Calculate kid to match JWK - must be identical to to_jwk() output
        let kid = self.calculate_kid(algorithm);

        let mut header = Header::new(alg);
        header.kid = Some(kid);

        encode(&header, claims, &encoding_key).map_err(|e| KeyError::FailedToSign(e.to_string()))
    }

    /// Manual JWT signing implementation for ES512 (P-521)
    ///
    /// Required because jsonwebtoken crate doesn't support ES512.
    /// Implements JWT signing per RFC 7519 with ES512 algorithm (RFC 7518).
    fn sign_jwt_es512(&self, claims: &Value) -> Result<String, KeyError> {
        let kid = self.calculate_kid(&KeySignAlgorithm::ES512);

        // Construct JWT header
        let header = json!({
            "alg": "ES512",
            "typ": "JWT",
            "kid": kid
        });

        // Base64url encode header and payload
        let header_json = serde_json::to_string(&header)
            .map_err(|e| KeyError::FailedToSign(format!("header serialization: {}", e)))?;
        let claims_json = serde_json::to_string(&claims)
            .map_err(|e| KeyError::FailedToSign(format!("claims serialization: {}", e)))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        // Create signing input: header.payload
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Hash the signing input with SHA-512 (per ES512 spec)
        let mut hasher = Sha512::new();
        hasher.update(signing_input.as_bytes());
        let message_hash = hasher.finalize();

        // Sign using P-521 key
        let signature: P521Signature = match &self.inner {
            EcdsaKey::P521(key) => key.sign(&message_hash),
            _ => {
                return Err(KeyError::FailedToSign(
                    "P-521 key required for ES512".to_string(),
                ))
            }
        };

        // Encode signature in base64url
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        // Construct final JWT: header.payload.signature
        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    /// Calculate Key ID (kid) for a given algorithm
    ///
    /// The kid is calculated as SHA-256 thumbprint per RFC 7638,
    /// suffixed with the algorithm to support multiple algorithms per key.
    fn calculate_kid(&self, alg: &KeySignAlgorithm) -> String {
        let (x_bytes, y_bytes) = match &self.inner {
            EcdsaKey::P256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                (
                    point.x().unwrap().as_slice().to_vec(),
                    point.y().unwrap().as_slice().to_vec(),
                )
            }
            EcdsaKey::P384(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                (
                    point.x().unwrap().as_slice().to_vec(),
                    point.y().unwrap().as_slice().to_vec(),
                )
            }
            EcdsaKey::P521(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                (
                    point.x().unwrap().as_slice().to_vec(),
                    point.y().unwrap().as_slice().to_vec(),
                )
            }
        };

        let x_b64 = URL_SAFE_NO_PAD.encode(&x_bytes);
        let y_b64 = URL_SAFE_NO_PAD.encode(&y_bytes);
        let crv = self.curve.as_str();

        // RFC 7638: SHA-256 of lexicographically ordered required members
        let thumbprint_input =
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#);
        let mut hasher = Sha256::new();
        hasher.update(thumbprint_input.as_bytes());
        let thumbprint = hasher.finalize();
        let kid_base = URL_SAFE_NO_PAD.encode(thumbprint);

        format!("{}-{}", kid_base, alg.as_str())
    }

    /// Export ECDSA public key as JSON Web Key (JWK)
    ///
    /// Returns a JWK representation according to RFC 7517 and RFC 7518.
    /// The Key ID (kid) is calculated as a SHA-256 thumbprint per RFC 7638.
    ///
    /// # Arguments
    /// * `alg` - The signing algorithm
    pub fn to_jwk(&self, alg: &KeySignAlgorithm) -> Value {
        let (x_bytes, y_bytes) = match &self.inner {
            EcdsaKey::P256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                (
                    point.x().unwrap().as_slice().to_vec(),
                    point.y().unwrap().as_slice().to_vec(),
                )
            }
            EcdsaKey::P384(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                (
                    point.x().unwrap().as_slice().to_vec(),
                    point.y().unwrap().as_slice().to_vec(),
                )
            }
            EcdsaKey::P521(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                (
                    point.x().unwrap().as_slice().to_vec(),
                    point.y().unwrap().as_slice().to_vec(),
                )
            }
        };

        let x_b64 = URL_SAFE_NO_PAD.encode(&x_bytes);
        let y_b64 = URL_SAFE_NO_PAD.encode(&y_bytes);

        let kid = self.calculate_kid(alg);

        json!({
            "kty": "EC",
            "use": "sig",
            "crv": self.curve.as_str(),
            "kid": kid,
            "alg": alg.as_str(),
            "x": x_b64,
            "y": y_b64
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
            KeyError::FileTooLarge { size, max } => {
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
            KeyError::InvalidRsaKeySize(1024)
        ));

        let result = RsaPrivateKey::generate(8192);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeyError::InvalidRsaKeySize(8192)
        ));
    }

    #[test]
    fn test_from_pem_invalid_format() {
        let result = RsaPrivateKey::from_pem("not a valid pem");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyError::FailedToDecodeRsa));
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
