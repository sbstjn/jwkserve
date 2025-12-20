use std::path::Path;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p521::ecdsa::{signature::Signer, Signature as P521Signature, SigningKey as P521SigningKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::utils::base64;
use crate::KeySignAlgorithm;

/// Maximum size for PEM-encoded keys (64KB)
const MAX_PEM_SIZE: usize = 64 * 1024;

/// Maximum size for key files (64KB)
const MAX_KEY_FILE_SIZE: u64 = 64 * 1024;

/// Validate PEM string size to prevent resource exhaustion
fn validate_pem_size(pem: &str) -> Result<(), KeyError> {
    if pem.len() > MAX_PEM_SIZE {
        return Err(KeyError::FileTooLarge {
            size: pem.len() as u64,
            max: MAX_PEM_SIZE as u64,
        });
    }
    Ok(())
}

/// Validate file size before reading to prevent resource exhaustion
fn validate_file_size(path: &Path) -> Result<(), KeyError> {
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
    Ok(())
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("invalid key size for {key_type}: {size} {constraint}")]
    InvalidKeySize {
        key_type: String,
        size: usize,
        constraint: String,
    },

    #[error("failed to generate {key_type} key")]
    FailedToGenerate { key_type: String },

    #[error("failed to encode {key_type} key to PEM format")]
    FailedToEncode { key_type: String },

    #[error("failed to decode {key_type} key from PEM format")]
    FailedToDecode { key_type: String },

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

#[derive(Clone, Debug)]
pub struct RsaPrivateKey {
    inner: rsa::RsaPrivateKey,
    pem_cache: String,
}

impl RsaPrivateKey {
    pub fn generate(bits: usize) -> Result<Self, KeyError> {
        if bits != 2048 && bits != 3072 && bits != 4096 {
            return Err(KeyError::InvalidKeySize {
                key_type: "RSA".to_string(),
                size: bits,
                constraint: "(must be 2048, 3072, or 4096)".to_string(),
            });
        }

        let mut rng = rand::thread_rng();
        let inner =
            rsa::RsaPrivateKey::new(&mut rng, bits).map_err(|_| KeyError::FailedToGenerate {
                key_type: "RSA".to_string(),
            })?;

        let pem_cache = inner
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| KeyError::FailedToEncode {
                key_type: "RSA".to_string(),
            })?
            .to_string();

        Ok(Self { inner, pem_cache })
    }

    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        validate_pem_size(pem)?;

        let inner =
            rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| KeyError::FailedToDecode {
                key_type: "RSA".to_string(),
            })?;

        Ok(Self {
            inner,
            pem_cache: pem.to_string(),
        })
    }

    pub fn from_pem_file(path: &Path) -> Result<Self, KeyError> {
        validate_file_size(path)?;

        let pem = std::fs::read_to_string(path).map_err(|e| KeyError::FailedToReadFile {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        Self::from_pem(&pem)
    }

    pub fn to_pem(&self) -> Result<String, KeyError> {
        Ok(self.pem_cache.clone())
    }

    pub fn to_public_pem(&self) -> Result<String, KeyError> {
        let public_key = RsaPublicKey::from(&self.inner);

        public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| KeyError::FailedToEncode {
                key_type: "RSA".to_string(),
            })
    }

    pub fn size_bits(&self) -> usize {
        self.inner.n().bits()
    }

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

        let encoding_key = EncodingKey::from_rsa_pem(self.pem_cache.as_bytes())
            .map_err(|e| KeyError::FailedToSign(e.to_string()))?;

        let kid = self.calculate_kid(algorithm);

        let mut header = Header::new(alg);
        header.kid = Some(kid);

        encode(&header, claims, &encoding_key).map_err(|e| KeyError::FailedToSign(e.to_string()))
    }

    fn calculate_kid(&self, alg: &KeySignAlgorithm) -> String {
        let n = self.inner.n().to_bytes_be();
        let e = self.inner.e().to_bytes_be();

        let n_b64 = base64::encode(&n);
        let e_b64 = base64::encode(&e);

        let thumbprint_input = format!(r#"{{"e":"{e_b64}","kty":"RSA","n":"{n_b64}"}}"#);
        let mut hasher = Sha256::new();
        hasher.update(thumbprint_input.as_bytes());
        let thumbprint = hasher.finalize();
        let kid_base = base64::encode(&thumbprint);

        format!("{}-{}", kid_base, alg.as_str())
    }

    pub fn to_jwk(&self, alg: &KeySignAlgorithm) -> Value {
        let n = self.inner.n().to_bytes_be();
        let e = self.inner.e().to_bytes_be();

        let n_b64 = base64::encode(&n);
        let e_b64 = base64::encode(&e);

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone, Debug)]
enum EcdsaKey {
    P256(P256SigningKey),
    P384(P384SigningKey),
    P521(P521SigningKey),
}

#[derive(Clone, Debug)]
pub struct EcdsaPrivateKey {
    inner: EcdsaKey,
    curve: EcdsaCurve,
    pem_cache: String,
}

impl EcdsaPrivateKey {
    fn extract_curve_point(&self) -> (Vec<u8>, Vec<u8>) {
        match &self.inner {
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
        }
    }

    pub fn generate(curve: EcdsaCurve) -> Result<Self, KeyError> {
        use elliptic_curve::pkcs8::EncodePrivateKey as EcEncodePrivateKey;

        let (inner, pem_cache) = match &curve {
            EcdsaCurve::P256 => {
                let key = P256SigningKey::generate();
                let pem = key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|_| KeyError::FailedToEncode {
                        key_type: "ECDSA P-256".to_string(),
                    })?
                    .to_string();
                (EcdsaKey::P256(key), pem)
            }
            EcdsaCurve::P384 => {
                let key = P384SigningKey::generate();
                let pem = key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|_| KeyError::FailedToEncode {
                        key_type: "ECDSA P-384".to_string(),
                    })?
                    .to_string();
                (EcdsaKey::P384(key), pem)
            }
            EcdsaCurve::P521 => {
                let key = P521SigningKey::generate();
                let pem = key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|_| KeyError::FailedToEncode {
                        key_type: "ECDSA P-521".to_string(),
                    })?
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

    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        use elliptic_curve::pkcs8::DecodePrivateKey as EcDecodePrivateKey;

        validate_pem_size(pem)?;

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

        Err(KeyError::FailedToDecode {
            key_type: "ECDSA".to_string(),
        })
    }

    pub fn from_pem_file(path: &Path) -> Result<Self, KeyError> {
        validate_file_size(path)?;

        let pem = std::fs::read_to_string(path).map_err(|e| KeyError::FailedToReadFile {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        Self::from_pem(&pem)
    }

    pub fn to_pem(&self) -> Result<String, KeyError> {
        Ok(self.pem_cache.clone())
    }

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

        pem.map_err(|_| KeyError::FailedToEncode {
            key_type: format!("ECDSA {}", self.curve.as_str()),
        })
    }

    pub fn curve(&self) -> &EcdsaCurve {
        &self.curve
    }

    pub fn sign_jwt(
        &self,
        claims: &Value,
        algorithm: &KeySignAlgorithm,
    ) -> Result<String, KeyError> {
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

        let encoding_key = EncodingKey::from_ec_pem(self.pem_cache.as_bytes())
            .map_err(|e| KeyError::FailedToSign(e.to_string()))?;

        let kid = self.calculate_kid(algorithm);

        let mut header = Header::new(alg);
        header.kid = Some(kid);

        encode(&header, claims, &encoding_key).map_err(|e| KeyError::FailedToSign(e.to_string()))
    }

    fn sign_jwt_es512(&self, claims: &Value) -> Result<String, KeyError> {
        let kid = self.calculate_kid(&KeySignAlgorithm::ES512);

        let header = json!({
            "alg": "ES512",
            "typ": "JWT",
            "kid": kid
        });

        let header_json = serde_json::to_string(&header)
            .map_err(|e| KeyError::FailedToSign(format!("header serialization: {}", e)))?;
        let claims_json = serde_json::to_string(&claims)
            .map_err(|e| KeyError::FailedToSign(format!("claims serialization: {}", e)))?;

        let header_b64 = base64::encode(header_json.as_bytes());
        let claims_b64 = base64::encode(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign the raw message - the ECDSA signer internally handles SHA-512 hashing
        // per RFC 7518 Section 3.4 (ES512 = ECDSA using P-521 and SHA-512)
        let signature: P521Signature = match &self.inner {
            EcdsaKey::P521(key) => key.sign(signing_input.as_bytes()),
            _ => {
                return Err(KeyError::FailedToSign(
                    "P-521 key required for ES512".to_string(),
                ))
            }
        };

        let signature_b64 = base64::encode(&signature.to_bytes());

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    fn calculate_kid(&self, alg: &KeySignAlgorithm) -> String {
        let (x_bytes, y_bytes) = self.extract_curve_point();

        let x_b64 = base64::encode(&x_bytes);
        let y_b64 = base64::encode(&y_bytes);
        let crv = self.curve.as_str();

        let thumbprint_input =
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#);
        let mut hasher = Sha256::new();
        hasher.update(thumbprint_input.as_bytes());
        let thumbprint = hasher.finalize();
        let kid_base = base64::encode(&thumbprint);

        format!("{}-{}", kid_base, alg.as_str())
    }

    pub fn to_jwk(&self, alg: &KeySignAlgorithm) -> Value {
        let (x_bytes, y_bytes) = self.extract_curve_point();

        let x_b64 = base64::encode(&x_bytes);
        let y_b64 = base64::encode(&y_bytes);

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
            KeyError::InvalidKeySize { .. }
        ));

        let result = RsaPrivateKey::generate(8192);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeyError::InvalidKeySize { .. }
        ));
    }

    #[test]
    fn test_from_pem_invalid_format() {
        let result = RsaPrivateKey::from_pem("not a valid pem");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeyError::FailedToDecode { .. }
        ));
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
