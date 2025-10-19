use serde::{Deserialize, Serialize};

use crate::key::KeyStore;

#[derive(Serialize, Deserialize, Clone)]
pub struct JsonWebKey {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub n: String,
    pub e: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

impl JsonWebKeySet {
    pub fn from_key_store(key_store: &KeyStore) -> Self {
        let kid = key_store.generate_kid();
        let signing_key = JsonWebKey {
            kid,
            kty: "RSA".into(),
            alg: "RS256".into(),
            key_use: "sig".into(),
            n: key_store.generate_n(),
            e: key_store.generate_e(),
        };

        Self {
            keys: vec![signing_key],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyStore;
    use std::sync::OnceLock;

    static SHARED_KEYSTORE: OnceLock<KeyStore> = OnceLock::new();

    fn get_shared_keystore() -> &'static KeyStore {
        SHARED_KEYSTORE.get_or_init(|| KeyStore::new())
    }

    #[test]
    fn test_jwks_creation_and_structure() {
        let keystore = get_shared_keystore();
        let jwks = JsonWebKeySet::from_key_store(keystore);

        // Verify JWKS structure
        assert_eq!(jwks.keys.len(), 1);

        let key = &jwks.keys[0];

        // Verify all required JWKS fields are present and correct
        assert!(!key.kid.is_empty());
        assert_eq!(key.kty, "RSA");
        assert_eq!(key.alg, "RS256");
        assert_eq!(key.key_use, "sig");
        assert!(!key.n.is_empty());
        assert!(!key.e.is_empty());
    }

    #[test]
    fn test_jwks_serialization_and_deserialization() {
        let keystore = get_shared_keystore();
        let original_jwks = JsonWebKeySet::from_key_store(keystore);

        // Test JSON serialization
        let json = serde_json::to_string(&original_jwks).expect("Should serialize to JSON");
        assert!(json.contains("\"keys\""));
        assert!(json.contains("\"kid\""));
        assert!(json.contains("\"kty\":\"RSA\""));
        assert!(json.contains("\"alg\":\"RS256\""));
        assert!(json.contains("\"use\":\"sig\"")); // Note: "use" not "key_use"
        assert!(json.contains("\"n\""));
        assert!(json.contains("\"e\""));

        // Test deserialization
        let deserialized_jwks: JsonWebKeySet =
            serde_json::from_str(&json).expect("Should deserialize");

        // Verify complete roundtrip consistency
        assert_eq!(original_jwks.keys.len(), deserialized_jwks.keys.len());

        let original_key = &original_jwks.keys[0];
        let deserialized_key = &deserialized_jwks.keys[0];

        assert_eq!(original_key.kid, deserialized_key.kid);
        assert_eq!(original_key.kty, deserialized_key.kty);
        assert_eq!(original_key.alg, deserialized_key.alg);
        assert_eq!(original_key.key_use, deserialized_key.key_use);
        assert_eq!(original_key.n, deserialized_key.n);
        assert_eq!(original_key.e, deserialized_key.e);
    }

    #[test]
    fn test_jwks_clone_functionality() {
        let keystore = get_shared_keystore();
        let original_jwks = JsonWebKeySet::from_key_store(keystore);
        let cloned_jwks = original_jwks.clone();

        // Verify clone produces identical structure
        assert_eq!(original_jwks.keys.len(), cloned_jwks.keys.len());
        assert_eq!(original_jwks.keys.len(), 1);

        let original_key = &original_jwks.keys[0];
        let cloned_key = &cloned_jwks.keys[0];

        // Verify all fields match
        assert_eq!(original_key.kid, cloned_key.kid);
        assert_eq!(original_key.kty, cloned_key.kty);
        assert_eq!(original_key.alg, cloned_key.alg);
        assert_eq!(original_key.key_use, cloned_key.key_use);
        assert_eq!(original_key.n, cloned_key.n);
        assert_eq!(original_key.e, cloned_key.e);
    }
}
