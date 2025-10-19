use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Clone)]
pub struct KeyStore {
    pub key: RsaPrivateKey,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
        Self { key }
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

        let key_content = fs::read_to_string(file_path)
            .unwrap_or_else(|_| panic!("Key file not found: {file_path}"));

        // Validate PEM content structure
        if !key_content.contains("-----BEGIN") || !key_content.contains("-----END") {
            panic!("Invalid PEM file format: {file_path}");
        }

        let key = RsaPrivateKey::from_pkcs8_pem(&key_content).expect("Failed to parse private key");

        Self { key }
    }

    pub fn generate_kid(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.generate_n().as_bytes());
        hasher.update(self.generate_e().as_bytes());
        hasher.update(b"RS256");
        hasher.update(b"sig");
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }

    pub fn generate_e(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.e().to_bytes_be())
    }

    pub fn generate_n(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.n().to_bytes_be())
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
    use num_bigint::BigUint;
    use std::fs;
    use std::sync::OnceLock;
    use tempfile::NamedTempFile;

    static SHARED_KEYSTORE: OnceLock<KeyStore> = OnceLock::new();

    fn get_shared_keystore() -> &'static KeyStore {
        SHARED_KEYSTORE.get_or_init(|| KeyStore::new())
    }

    #[test]
    fn test_new_creates_valid_keystore() {
        let keystore = get_shared_keystore();

        // Verify we can generate KID without panicking
        let _kid = keystore.generate_kid();
        let _e = keystore.generate_e();
        let _n = keystore.generate_n();
        let _public_key = keystore.public_key();
        let _pem = keystore.to_pkcs8_pem();
    }

    #[test]
    fn test_new_generates_different_keys() {
        let keystore1 = KeyStore::new();
        let keystore2 = KeyStore::new();

        // Different keys should have different KIDs
        assert_ne!(keystore1.generate_kid(), keystore2.generate_kid());
        assert_ne!(keystore1.generate_n(), keystore2.generate_n());
    }

    #[test]
    fn test_generated_key_has_correct_bit_length() {
        let keystore = get_shared_keystore();
        let public_key = keystore.public_key();

        // RSA 2048-bit key should have 256 bytes for n (2048/8)
        assert_eq!(public_key.n().to_bytes_be().len(), 256);
    }

    #[test]
    fn test_from_file_loads_valid_key() {
        let keystore = KeyStore::new();
        let pem_content = keystore.to_pkcs8_pem();

        // Create temporary file with valid PEM content
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(temp_file.path(), pem_content).expect("Failed to write to temp file");

        let loaded_keystore = KeyStore::from_file(temp_file.path().to_str().unwrap());

        // Verify the loaded key produces the same KID
        assert_eq!(keystore.generate_kid(), loaded_keystore.generate_kid());
    }

    #[test]
    #[should_panic(expected = "Key file not found")]
    fn test_from_file_panics_on_missing_file() {
        KeyStore::from_file("nonexistent_file.pem");
    }

    #[test]
    #[should_panic(expected = "Invalid PEM file format")]
    fn test_from_file_panics_on_invalid_pem() {
        // Create temporary file with invalid PEM content
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(temp_file.path(), "invalid pem content").expect("Failed to write to temp file");

        KeyStore::from_file(temp_file.path().to_str().unwrap());
    }

    #[test]
    fn test_generate_kid_deterministic() {
        let keystore = get_shared_keystore();
        let kid1 = keystore.generate_kid();
        let kid2 = keystore.generate_kid();

        // Same key should produce same KID
        assert_eq!(kid1, kid2);
    }

    #[test]
    fn test_generate_kid_different_for_different_keys() {
        let keystore = get_shared_keystore();
        let keystore2 = KeyStore::new();

        let kid1 = keystore.generate_kid();
        let kid2 = keystore2.generate_kid();

        // Different keys should produce different KIDs
        assert_ne!(kid1, kid2);
    }

    #[test]
    fn test_generate_e_and_n_return_base64_url_safe() {
        let keystore = get_shared_keystore();
        let e = keystore.generate_e();
        let n = keystore.generate_n();

        // Both should be valid base64url without padding
        for value in [&e, &n] {
            assert!(!value.contains('+'));
            assert!(!value.contains('/'));
            assert!(!value.contains('='));
            assert!(!value.contains('\n'));
        }
    }

    #[test]
    fn test_public_key_matches_private_key() {
        let keystore = get_shared_keystore();
        let public_key = keystore.public_key();

        // Public key should have same n and e as private key
        assert_eq!(public_key.n(), keystore.key.n());
        assert_eq!(public_key.e(), keystore.key.e());
    }

    #[test]
    fn test_to_pkcs8_pem_roundtrip() {
        let original_keystore = KeyStore::new();
        let pem_content = original_keystore.to_pkcs8_pem();

        // Create temporary file and load it back
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(temp_file.path(), pem_content).expect("Failed to write to temp file");

        let loaded_keystore = KeyStore::from_file(temp_file.path().to_str().unwrap());

        // Should produce identical results
        assert_eq!(
            original_keystore.generate_kid(),
            loaded_keystore.generate_kid()
        );
        assert_eq!(original_keystore.generate_e(), loaded_keystore.generate_e());
        assert_eq!(original_keystore.generate_n(), loaded_keystore.generate_n());
    }

    #[test]
    fn test_kid_components() {
        let keystore = get_shared_keystore();
        let n = keystore.generate_n();
        let e = keystore.generate_e();
        let kid = keystore.generate_kid();

        // Manually compute expected KID
        let mut hasher = Sha256::new();
        hasher.update(n.as_bytes());
        hasher.update(e.as_bytes());
        hasher.update(b"RS256");
        hasher.update(b"sig");
        let expected_kid = URL_SAFE_NO_PAD.encode(hasher.finalize());

        assert_eq!(kid, expected_kid);
    }

    #[test]
    fn test_clone_creates_identical_keystore() {
        let keystore1 = get_shared_keystore();
        let keystore2 = keystore1.clone();

        // Cloned keystore should produce identical results
        assert_eq!(keystore1.generate_kid(), keystore2.generate_kid());
        assert_eq!(keystore1.generate_e(), keystore2.generate_e());
        assert_eq!(keystore1.generate_n(), keystore2.generate_n());
    }

    #[test]
    fn test_generate_e_and_n_are_valid_base64() {
        let keystore = get_shared_keystore();
        let e = keystore.generate_e();
        let n = keystore.generate_n();

        // Should be valid base64 that can be decoded
        for value in [&e, &n] {
            let decoded = URL_SAFE_NO_PAD
                .decode(value)
                .expect("Should be valid base64");
            assert!(!decoded.is_empty());
        }
    }

    #[test]
    fn test_from_file_panics_on_empty_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(temp_file.path(), "").expect("Failed to write to temp file");

        // Should panic on empty file
        let result = std::panic::catch_unwind(|| {
            KeyStore::from_file(temp_file.path().to_str().unwrap());
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_panics_on_whitespace_only_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(temp_file.path(), "   \n\t  \n  ").expect("Failed to write to temp file");

        // Should panic on whitespace-only file
        let result = std::panic::catch_unwind(|| {
            KeyStore::from_file(temp_file.path().to_str().unwrap());
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_kid_has_consistent_length() {
        let keystore1 = get_shared_keystore();
        let keystore2 = KeyStore::new(); // Need a second key for comparison

        let kid1 = keystore1.generate_kid();
        let kid2 = keystore2.generate_kid();

        // All KIDs should have the same length (base64url of SHA256 = 43 chars)
        assert_eq!(kid1.len(), 43);
        assert_eq!(kid2.len(), 43);
    }

    #[test]
    fn test_generate_kid_uses_url_safe_chars() {
        let keystore = get_shared_keystore();
        let kid = keystore.generate_kid();

        // KID should only contain URL-safe base64 characters
        for ch in kid.chars() {
            assert!(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
        }
    }

    #[test]
    fn test_generate_e_has_expected_value() {
        let keystore = get_shared_keystore();
        let e = keystore.generate_e();

        // Decode and verify it's the standard RSA exponent (65537)
        let decoded = URL_SAFE_NO_PAD.decode(&e).expect("Should be valid base64");
        let exponent = BigUint::from_bytes_be(&decoded);
        assert_eq!(exponent, BigUint::from(65537u32));
    }

    #[test]
    fn test_generate_n_has_consistent_length() {
        let keystore1 = get_shared_keystore();
        let keystore2 = KeyStore::new(); // Need a second key for comparison

        let n1 = keystore1.generate_n();
        let n2 = keystore2.generate_n();

        // All moduli should have the same length (base64url of 256 bytes = 342 chars)
        assert_eq!(n1.len(), 342);
        assert_eq!(n2.len(), 342);
    }

    #[test]
    #[should_panic(expected = "Key file not found or not a file")]
    fn test_from_file_panics_on_directory() {
        KeyStore::from_file("/tmp");
    }

    #[test]
    #[should_panic(expected = "Failed to parse private key")]
    fn test_from_file_panics_on_malformed_pem_headers() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::write(
            temp_file.path(),
            "-----BEGIN PRIVATE KEY-----\ninvalid content\n-----END PRIVATE KEY-----",
        )
        .expect("Failed to write to temp file");

        KeyStore::from_file(temp_file.path().to_str().unwrap());
    }
}
