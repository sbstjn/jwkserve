use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::EncodingKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct Key {
    key: RsaPrivateKey,
    encoding_key: Arc<EncodingKey>,
    kid: String,
    n: String,
    e: String,
}

impl Default for Key {
    fn default() -> Self {
        Self::new()
    }
}

impl Key {
    /// Helper function to pre-compute all cached values from an RSA key
    fn compute_cached_values(key: &RsaPrivateKey) -> (Arc<EncodingKey>, String, String, String) {
        // Pre-compute n and e
        let e = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
        let n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());

        // Pre-compute kid from n, e, alg, and use
        let mut hasher = Sha256::new();
        hasher.update(n.as_bytes());
        hasher.update(e.as_bytes());
        hasher.update(b"RS256");
        hasher.update(b"sig");
        let kid = URL_SAFE_NO_PAD.encode(hasher.finalize());

        // Pre-compute encoding key
        let pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key")
            .to_string();
        let encoding_key = Arc::new(
            EncodingKey::from_rsa_pem(pem.as_bytes()).expect("Failed to create encoding key"),
        );

        (encoding_key, kid, n, e)
    }

    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
        let (encoding_key, kid, n, e) = Self::compute_cached_values(&key);

        Self {
            key,
            encoding_key,
            kid,
            n,
            e,
        }
    }

    pub fn from_file(file_path: &str) -> Self {
        // Validate file path
        let path = Path::new(file_path);
        if !path.is_file() {
            panic!("Key file not found or not a file: {file_path}");
        }

        // Check file size (max 1MB for PEM files)
        let metadata =
            fs::metadata(path).unwrap_or_else(|_| panic!("Cannot read file metadata: {file_path}"));
        if metadata.len() > 1_048_576 {
            panic!("Key file too large (max 1MB): {file_path}");
        }

        // Read file content
        let key_content = fs::read_to_string(file_path)
            .unwrap_or_else(|_| panic!("Key file not found: {file_path}"));

        // Validate PEM content structure
        if !key_content.contains("-----BEGIN") || !key_content.contains("-----END") {
            panic!("Invalid PEM file format: {file_path}");
        }

        let key = RsaPrivateKey::from_pkcs8_pem(&key_content).expect("Failed to parse private key");
        let (encoding_key, kid, n, e) = Self::compute_cached_values(&key);

        Self {
            key,
            encoding_key,
            kid,
            n,
            e,
        }
    }

    /// Returns a reference to the cached encoding key.
    /// This eliminates the need to convert to PEM and re-parse on every request.
    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding_key
    }

    /// Returns a reference to the cached key ID (kid).
    /// Pre-computed from SHA256(n + e + alg + use).
    pub fn generate_kid(&self) -> &str {
        &self.kid
    }

    /// Returns a reference to the cached public exponent (e) in base64url format.
    pub fn generate_e(&self) -> &str {
        &self.e
    }

    /// Returns a reference to the cached modulus (n) in base64url format.
    pub fn generate_n(&self) -> &str {
        &self.n
    }

    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey::from(&self.key)
    }

    pub fn to_pkcs8_pem(&self) -> String {
        self.key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::OnceLock;
    use tempfile::NamedTempFile;

    static SHARED_KEYSTORE: OnceLock<Key> = OnceLock::new();

    fn get_shared_key() -> &'static Key {
        SHARED_KEYSTORE.get_or_init(|| Key::new())
    }

    /// Generate keys
    #[test]
    fn test_key_generation() {
        let keystore = get_shared_key();
        let kid = keystore.generate_kid();

        // Generate kid
        let kid2 = keystore.generate_kid();
        assert_eq!(kid, kid2);

        // Generate kid for new key
        let keystore2 = Key::new();
        let kid3 = keystore2.generate_kid();
        assert_ne!(kid, kid3);
    }

    /// Load keys from file
    #[test]
    fn test_from_file() {
        let keystore = get_shared_key();
        let pem_content = keystore.to_pkcs8_pem();

        // Create temporary file with valid PEM content
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(temp_file.path(), pem_content).expect("Failed to write to temp file");

        let loaded_keystore = Key::from_file(temp_file.path().to_str().unwrap());

        // loaded key should produce same KID (roundtrip works)
        assert_eq!(keystore.generate_kid(), loaded_keystore.generate_kid());
    }

    /// Invalid key format
    #[test]
    #[should_panic(expected = "Invalid PEM file format")]
    fn test_from_file_panics_on_invalid_pem() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(temp_file.path(), "invalid pem content").expect("Failed to write to temp file");
        Key::from_file(temp_file.path().to_str().unwrap());
    }

    /// Key file too large
    #[test]
    #[should_panic(expected = "Key file too large")]
    fn test_from_file_panics_on_large_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");

        // Create a file larger than 1MB
        let large_content = "x".repeat(1_048_577);
        fs::write(temp_file.path(), large_content).expect("Failed to write to temp file");
        Key::from_file(temp_file.path().to_str().unwrap());
    }

    /// Directory instead of file
    #[test]
    #[should_panic(expected = "Key file not found or not a file")]
    fn test_from_file_panics_on_directory() {
        Key::from_file("/tmp");
    }
}
